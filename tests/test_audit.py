"""Tests for api-key-leak-check. Standard library only.

Each test builds a fake home folder with fake OpenClaw and Hermes agents,
plants randomly generated keys, and runs the real scripts against it.

Run: python -m unittest discover -s tests -v
"""

import ast
import json
import os
import secrets
import shutil
import stat
import string
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SKILL = os.path.join(ROOT, "skills", "api-key-leak-check")
AUDIT = os.path.join(SKILL, "scripts", "audit.py")
FIX = os.path.join(SKILL, "scripts", "fix.py")
POSIX = os.name != "nt"


def rand(n):
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(n))


class Base(unittest.TestCase):
    def setUp(self):
        self.home = tempfile.mkdtemp(prefix="leakcheck-")
        self.addCleanup(shutil.rmtree, self.home, True)
        self.env = {k: v for k, v in os.environ.items()
                    if not k.startswith(("OPENCLAW_", "HERMES_"))}
        # Windows finds the home folder from USERPROFILE, everything else from HOME.
        self.env["HOME"] = self.home
        self.env["USERPROFILE"] = self.home
        self.planted = []

    def write(self, rel, text, mode=0o600):
        path = os.path.join(self.home, *rel.split("/"))
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)
        if POSIX:
            os.chmod(path, mode)
        return path

    def key(self, prefix, n):
        k = prefix + rand(n)
        self.planted.append(k)
        return k

    def run_script(self, script, *args):
        p = subprocess.run([sys.executable, "-I", script] + list(args), env=self.env,
                           cwd=self.home, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return p.returncode, p.stdout.decode("utf-8"), p.stderr.decode("utf-8")

    def audit(self, *args):
        code, out, err = self.run_script(AUDIT, *args)
        self.assertEqual(err, "", err)
        return out

    def audit_json(self):
        return json.loads(self.audit("--json"))

    def fix(self, *args):
        return self.run_script(FIX, *args)

    def ids(self, rep, **match):
        return [f["id"] for f in rep["findings"] if all(f.get(k) == v for k, v in match.items())]

    def assert_no_full_key(self, *texts):
        for text in texts:
            for k in self.planted:
                self.assertNotIn(k, text, "a full key was printed")


class FindsKeys(Base):
    def plant_everywhere(self):
        self.write(".openclaw/workspace/MEMORY.md", "- Stripe key for invoices: %s\n" % self.key("sk_live_", 40))
        self.write(".hermes/.env", "OPENROUTER_API_KEY=%s\nNOTION_API_KEY=%s\n"
                   % (self.key("sk-or-v1-", 64), self.key("ntn_", 44)))
        self.write(".openclaw/skills/github/SKILL.md", "---\nname: github\ndescription: g\n---\nSee scripts.\n")
        self.write(".openclaw/skills/github/scripts/gh.py",
                   'import requests\nTOKEN = "%s"\nrequests.get("https://api.github.com/user", '
                   'headers={"Authorization": "token " + TOKEN})\n' % self.key("ghp_", 36))
        self.write(".zshrc", "export PATH=$PATH:/x\nexport RESEND_API_KEY=%s\n"
                   % self.key("re_" + rand(8) + "_", 24))

    def test_finds_keys_in_every_place(self):
        self.plant_everywhere()
        rep = self.audit_json()
        groups = {g["group"] for g in rep["groups"]}
        for g in ("memory", "app-keys", "skill-secret", "shell", "agent-logins"):
            self.assertIn(g, groups)
        self.assertEqual(rep["status"], "ACTION NEEDED")
        self.assertIn("Stripe", rep["headline"])

    def test_never_prints_a_full_key(self):
        self.plant_everywhere()
        report = os.path.join(self.home, "report.md")
        outputs = [self.audit(), self.audit("--details"), self.audit("--json"),
                   self.audit("--markdown", report)]
        with open(report, encoding="utf-8") as fh:
            outputs.append(fh.read())
        self.assert_no_full_key(*outputs)

    def test_output_is_plain_ascii(self):
        self.plant_everywhere()
        for out in (self.audit(), self.audit("--details")):
            self.assertTrue(all(ord(c) < 128 for c in out))

    def test_placeholders_are_not_keys(self):
        self.write(".hermes/.env", "NOTION_API_KEY=your-notion-key-here\n")
        self.write(".openclaw/workspace/MEMORY.md", "Example: sk_test_xxxxxxxxxxxxxxxxxxxxxxxx\n")
        self.assertEqual(self.audit_json()["status"], "ALL CLEAR")

    def test_real_key_with_placeholder_letters_inside_is_found(self):
        # A random key can contain "Your" or "xxxx" by chance; it's still a key.
        k = "sk_live_" + rand(10) + "Your" + rand(10) + "xxxx" + rand(10)
        self.planted.append(k)
        self.write(".hermes/.env", "STRIPE_SECRET_KEY=%s\n" % k)
        rep = self.audit_json()
        self.assertEqual([f["provider"] for f in rep["findings"] if f["kind"] == "secret"], ["stripe"])

    def test_agents_own_locked_key_is_normal(self):
        self.write(".hermes/.env", "ANTHROPIC_API_KEY=%s\n" % self.key("sk-ant-api03-", 60))
        rep = self.audit_json()
        self.assertEqual(rep["status"], "ALL CLEAR")
        self.assertEqual([f["group"] for f in rep["findings"]], ["agent-logins"])

    @unittest.skipUnless(POSIX, "file permissions are only checked on macOS and Linux")
    def test_flags_file_others_can_open(self):
        self.write(".hermes/.env", "NOTION_API_KEY=%s\n" % self.key("ntn_", 44), mode=0o644)
        self.assertIn("open-files", {g["group"] for g in self.audit_json()["groups"]})

    def test_skill_using_key_from_env(self):
        self.write(".hermes/skills/notion/SKILL.md", '---\nname: notion\ndescription: n\n---\n'
                   'curl https://api.notion.com/v1/pages -H "Authorization: Bearer $NOTION_API_KEY"\n')
        rep = self.audit_json()
        self.assertEqual([s["name"] for s in rep["skills"] if s["swytchcode_can_replace"]], ["notion"])

    def test_keyless_public_api_is_not_flagged(self):
        self.write(".hermes/skills/arxiv/SKILL.md", "---\nname: arxiv\ndescription: a\n---\n"
                   "curl https://api.semanticscholar.org/graph/v1/paper/search?q=cat\n")
        self.assertEqual(self.audit_json()["status"], "ALL CLEAR")

    def test_copies_of_this_skill_dont_flag_themselves(self):
        for agent in (".hermes", ".openclaw"):
            shutil.copytree(SKILL, os.path.join(self.home, agent, "skills", "api-key-leak-check"))
        self.assertEqual(self.audit_json()["status"], "ALL CLEAR")

    def test_no_agent_found(self):
        code, out, _ = self.run_script(AUDIT)
        self.assertEqual(code, 2)
        self.assertIn("Couldn't find", out)


class NamesTheAgent(Base):
    def test_names_agent_when_both_are_installed(self):
        self.write(".openclaw/workspace/MEMORY.md", "stripe: %s\n" % self.key("sk_live_", 40))
        self.write(".hermes/memories/MEMORY.md", "notes\n")
        out = self.audit()
        self.assertIn("your OpenClaw agent's memory", out)
        self.assertIn("URGENT: [OpenClaw]", out)
        self.assertIn("Agent: OpenClaw", self.audit("--details"))

    def test_no_agent_names_with_one_agent(self):
        self.write(".hermes/memories/MEMORY.md", "github: %s\n" % self.key("ghp_", 36))
        out = self.audit()
        self.assertNotIn("[Hermes]", out)
        self.assertIn("your agent's memory", out)


class Fixes(Base):
    def snapshot(self):
        files = {}
        for d, _, names in os.walk(self.home):
            for n in names:
                p = os.path.join(d, n)
                with open(p, "rb") as fh:
                    files[p] = (fh.read(), os.stat(p).st_mode)
        return files

    def test_dry_run_changes_nothing(self):
        self.write(".openclaw/workspace/MEMORY.md", "keep\nstripe: %s\n" % self.key("sk_live_", 40), mode=0o644)
        self.write(".hermes/config.yaml.bak.1", "api_key: %s\n" % self.key("sk-ant-api03-", 60))
        rep = self.audit_json()
        before = self.snapshot()
        code, out, _ = self.fix("--dry-run", *[f["id"] for f in rep["findings"]])
        self.assertIn("Will do:", out)
        self.assertEqual(before, self.snapshot())

    def test_removes_key_line_and_keeps_the_rest(self):
        self.write(".openclaw/workspace/MEMORY.md", "keep me\nstripe: %s\nkeep me too\n" % self.key("sk_live_", 40))
        self.write(".zshrc", "export A=1\nexport STRIPE_SECRET_KEY=%s\nexport GITHUB_TOKEN=%s\nexport B=2\n"
                   % (self.key("sk_live_", 40), self.key("ghp_", 36)))
        rep = self.audit_json()
        code, out, _ = self.fix(*self.ids(rep, action="remove-line"))
        self.assertEqual(code, 0, out)
        with open(os.path.join(self.home, ".openclaw", "workspace", "MEMORY.md"), encoding="utf-8") as fh:
            self.assertEqual(fh.read(), "keep me\nkeep me too\n")
        with open(os.path.join(self.home, ".zshrc"), encoding="utf-8") as fh:
            self.assertEqual(fh.read(), "export A=1\nexport B=2\n")
        self.assertEqual(self.audit_json()["status"], "ALL CLEAR")

    def test_blanks_key_in_settings_and_file_stays_valid(self):
        path = self.write(".openclaw/openclaw.json", json.dumps(
            {"skills": {"entries": {"stripe": {"env": {"STRIPE_SECRET_KEY": self.key("sk_live_", 40)}}}}}, indent=2))
        rep = self.audit_json()
        code, out, _ = self.fix(*self.ids(rep, action="blank"))
        self.assertEqual(code, 0, out)
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        self.assertEqual(data["skills"]["entries"]["stripe"]["env"]["STRIPE_SECRET_KEY"], "")
        self.assert_no_full_key(out)

    def test_deletes_old_backup(self):
        path = self.write(".hermes/state-snapshots/old/.env", "NOTION_API_KEY=%s\n" % self.key("ntn_", 44))
        rep = self.audit_json()
        code, out, _ = self.fix(*self.ids(rep, action="delete"))
        self.assertEqual(code, 0, out)
        self.assertFalse(os.path.exists(path))

    def test_refuses_agents_own_key(self):
        path = self.write(".hermes/.env", "ANTHROPIC_API_KEY=%s\n" % self.key("sk-ant-api03-", 60))
        rep = self.audit_json()
        with open(path, "rb") as fh:
            before = fh.read()
        code, out, _ = self.fix(*self.ids(rep, group="agent-logins"))
        self.assertEqual(code, 1)
        self.assertIn("your agent needs this key", out)
        with open(path, "rb") as fh:
            self.assertEqual(before, fh.read())

    def test_unknown_id(self):
        self.write(".hermes/memories/MEMORY.md", "notes\n")
        code, out, _ = self.fix("deadbeef")
        self.assertEqual(code, 1)
        self.assertIn("not found", out)

    @unittest.skipUnless(POSIX, "locking files is only needed on macOS and Linux")
    def test_locks_file(self):
        path = self.write(".hermes/.env", "NOTION_API_KEY=%s\n" % self.key("ntn_", 44), mode=0o644)
        rep = self.audit_json()
        code, out, _ = self.fix(*self.ids(rep, action="lock"))
        self.assertEqual(code, 0, out)
        self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)


class MoreWhere(Base):
    def test_key_in_chat_database(self):
        import sqlite3
        os.makedirs(os.path.join(self.home, ".hermes"))
        db = sqlite3.connect(os.path.join(self.home, ".hermes", "state.db"))
        db.execute("create table messages (content text)")
        db.execute("insert into messages values (?)", ("my token is %s" % self.key("ghp_", 36),))
        db.commit()
        db.close()
        rep = self.audit_json()
        found = [f for f in rep["findings"] if f["path"].endswith(("state.db", "state.db-wal"))]
        files = sorted(os.listdir(os.path.join(self.home, ".hermes")))
        self.assertEqual([(f["group"], f["action"]) for f in found], [("memory", "chat-db")],
                         "sqlite %s, files %s" % (sqlite3.sqlite_version, files))
        self.assert_no_full_key(self.audit(), self.audit("--details"), json.dumps(rep))

    def test_key_in_recent_chats_of_a_running_agent(self):
        # A running Hermes holds state.db open in WAL mode: new messages sit in
        # state.db-wal until SQLite moves them into state.db.
        import sqlite3
        os.makedirs(os.path.join(self.home, ".hermes"))
        path = os.path.join(self.home, ".hermes", "state.db")
        db = sqlite3.connect(path)
        self.addCleanup(db.close)
        db.execute("pragma journal_mode=wal")
        db.execute("pragma wal_autocheckpoint=0")
        db.execute("create table messages (content text)")
        db.commit()
        db.execute("insert into messages values (?)", ("my token is %s" % self.key("ghp_", 36),))
        db.commit()
        with open(path, "rb") as fh:
            self.assertNotIn(self.planted[-1].encode(), fh.read(), "test setup: key should only be in the WAL")
        found = [f for f in self.audit_json()["findings"] if f["path"].endswith("state.db-wal")]
        self.assertEqual([(f["group"], f["action"]) for f in found], [("memory", "chat-db")])

    def test_key_in_powershell_profile(self):
        self.write(".hermes/memories/MEMORY.md", "notes\n")
        self.write("Documents/PowerShell/Microsoft.PowerShell_profile.ps1",
                   '$env:GITHUB_TOKEN = "%s"\n' % self.key("ghp_", 36))
        self.assertIn("shell", {g["group"] for g in self.audit_json()["groups"]})

    def test_markdown_report(self):
        self.write(".hermes/memories/MEMORY.md", "github: %s\n" % self.key("ghp_", 36))
        report = os.path.join(self.home, "report.md")
        self.audit("--markdown", report)
        with open(report, encoding="utf-8") as fh:
            text = fh.read()
        self.assertIn("# Agent security check: action needed", text)
        self.assertIn("## What we found", text)
        self.assertIn("## Details", text)
        self.assert_no_full_key(text)

    def test_memory_says_sent_with_every_message(self):
        self.write(".hermes/memories/MEMORY.md", "github: %s\n" % self.key("ghp_", 36))
        self.assertIn("sent to your AI provider with every message", self.audit())

    def test_chat_history_doesnt_claim_every_message(self):
        self.write(".openclaw/agents/main/sessions/abc.jsonl",
                   json.dumps({"content": "key %s" % self.key("sk_live_", 40)}) + "\n")
        out = self.audit()
        self.assertIn("chat history", out)
        self.assertNotIn("every message", out)

    def test_names_of_functions_in_code_are_not_keys(self):
        self.write(".hermes/skills/tool/SKILL.md", "---\nname: tool\ndescription: t\n---\nRun it.\n")
        self.write(".hermes/skills/tool/scripts/run.py",
                   "token = refresh_token_from_store\nEXPLAIN = {'skill-secret': explain_skill_secret}\n")
        self.assertEqual(self.audit_json()["status"], "ALL CLEAR")

    def test_password_made_of_words_in_settings_is_found(self):
        self.write(".hermes/.env", "DB_PASSWORD=correct_horse_battery_staple_mango\n")
        rep = self.audit_json()
        self.assertTrue([f for f in rep["findings"] if f["kind"] == "secret"])

    def test_short_password_in_settings_is_found(self):
        self.write(".hermes/.env", "DB_PASSWORD=hunter22x\n")
        self.write(".hermes/config.yaml", 'smtp_password: "p@ss!w0rd9"\n')
        rep = self.audit_json()
        self.assertEqual(len([f for f in rep["findings"] if f["kind"] == "secret"]), 2)
        self.assertNotEqual(rep["status"], "ALL CLEAR")
        self.assertNotIn("hunter22x", self.audit("--details"))

    def test_password_references_are_not_passwords(self):
        self.write(".hermes/config.yaml", "password: ${DB_PASSWORD}\npassword_env: DB_PASS\n"
                   "admin_password: changeme123\n")
        self.write(".hermes/.env", "PWD=/home/me/project\n")
        self.write(".hermes/skills/tool/SKILL.md", "---\nname: tool\ndescription: t\n---\nRun it.\n")
        self.write(".hermes/skills/tool/scripts/run.py", "password = get_password()\npwd = os.getcwd()\n")
        self.assertEqual(self.audit_json()["status"], "ALL CLEAR")

    @unittest.skipUnless(POSIX, "links need extra rights on Windows")
    def test_linked_skill_folder_is_checked(self):
        # `npx skills add` can link a skill in from ~/.agents/skills.
        self.write(".agents/skills/billing/SKILL.md", "---\nname: billing\ndescription: b\n---\n"
                   "Use key %s\n" % self.key("sk_live_", 40))
        os.makedirs(os.path.join(self.home, ".openclaw", "skills"))
        self.write(".openclaw/openclaw.json", "{}\n")
        os.symlink(os.path.join(self.home, ".agents", "skills", "billing"),
                   os.path.join(self.home, ".openclaw", "skills", "billing"))
        rep = self.audit_json()
        self.assertTrue([f for f in rep["findings"] if f["group"] == "skill-secret" and f["skill"] == "billing"])

    @unittest.skipUnless(POSIX, "links need extra rights on Windows")
    def test_link_loop_in_a_skill_does_not_hang(self):
        self.write(".hermes/skills/loop/SKILL.md", "---\nname: loop\ndescription: l\n---\nHi.\n")
        os.symlink(os.path.join(self.home, ".hermes", "skills", "loop"),
                   os.path.join(self.home, ".hermes", "skills", "loop", "again"))
        self.assertEqual(self.audit_json()["status"], "ALL CLEAR")

    def test_openclaw_readme_is_not_sent_with_every_message(self):
        self.write(".openclaw/workspace/README.md", "github: %s\n" % self.key("ghp_", 36))
        out = self.audit()
        self.assertIn("memory notes", out)
        self.assertNotIn("every message", out)

    def test_openclaw_soul_is_sent_with_every_message(self):
        self.write(".openclaw/workspace/SOUL.md", "github: %s\n" % self.key("ghp_", 36))
        self.assertIn("sent to your AI provider with every message", self.audit())

    def test_other_memory_notes_are_not_called_chat_history(self):
        self.write(".hermes/memories/archive/old.md", "github: %s\n" % self.key("ghp_", 36))
        out = self.audit()
        self.assertIn("memory notes", out)
        self.assertNotIn("chat history", out)
        self.assertNotIn("every message", out)


@unittest.skipUnless(POSIX, "file permissions are only checked on macOS and Linux")
class GroupAccess(unittest.TestCase):
    """Ubuntu makes new files readable by the user's own private group."""

    def setUp(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location("audit_under_test", AUDIT)
        self.audit = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.audit)
        fd, self.path = tempfile.mkstemp()
        os.close(fd)
        self.addCleanup(os.unlink, self.path)

    def check(self, mode, group_has_others):
        os.chmod(self.path, mode)
        self.audit._GROUP_CACHE.clear()
        self.audit.group_has_others = lambda gid: group_has_others
        return self.audit.others_can_read(self.path)

    def test_group_readable_with_only_me_in_group_is_fine(self):
        self.assertFalse(self.check(0o640, group_has_others=False))

    def test_group_readable_with_others_in_group_is_flagged(self):
        self.assertTrue(self.check(0o640, group_has_others=True))

    def test_readable_by_everyone_is_always_flagged(self):
        self.assertTrue(self.check(0o644, group_has_others=False))

    def test_locked_file_is_fine(self):
        self.assertFalse(self.check(0o600, group_has_others=True))

    def test_file_owned_by_another_account_is_flagged(self):
        real_stat = os.stat
        fake = os.stat_result((stat.S_IFREG | 0o600, 0, 0, 1, os.getuid() + 1, 0, 0, 0, 0, 0))
        with mock.patch.object(self.audit.os, "stat", lambda p, *a, **k: fake if p == self.path else real_stat(p, *a, **k)):
            self.assertTrue(self.audit.others_can_read(self.path))


@unittest.skipUnless(POSIX, "groups are only checked on macOS and Linux")
class GroupMembers(unittest.TestCase):
    """The real group lookup, with made-up accounts and groups."""

    def setUp(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location("audit_under_test", AUDIT)
        self.audit = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.audit)
        self.uid = os.getuid()

    def has_others(self, gid, groups, users):
        import types
        me = next(u for u in users if u.pw_uid == self.uid)

        def getgrgid(g):
            if g not in groups:
                raise KeyError(g)
            return groups[g]
        fake_grp = types.SimpleNamespace(getgrgid=getgrgid)
        fake_pwd = types.SimpleNamespace(getpwuid=lambda u: me, getpwall=lambda: users)
        self.audit._GROUP_CACHE.clear()
        with mock.patch.dict(sys.modules, {"grp": fake_grp, "pwd": fake_pwd}):
            return self.audit.group_has_others(gid)

    def user(self, name, uid, gid):
        import types
        return types.SimpleNamespace(pw_name=name, pw_uid=uid, pw_gid=gid)

    def group(self, name, members=()):
        import types
        return types.SimpleNamespace(gr_name=name, gr_mem=list(members))

    def test_own_private_group_is_only_me(self):
        users = [self.user("ana", self.uid, 1000), self.user("bo", self.uid + 1, 1001)]
        self.assertFalse(self.has_others(1000, {1000: self.group("ana")}, users))

    def test_someone_added_to_my_group(self):
        users = [self.user("ana", self.uid, 1000)]
        self.assertTrue(self.has_others(1000, {1000: self.group("ana", ["bo"])}, users))

    def test_someone_else_with_my_group_as_main_group(self):
        users = [self.user("ana", self.uid, 1000), self.user("bo", self.uid + 1, 1000)]
        self.assertTrue(self.has_others(1000, {1000: self.group("ana")}, users))

    def test_shared_group_counts_as_others_even_if_none_listed(self):
        users = [self.user("ana", self.uid, 1000)]
        self.assertTrue(self.has_others(20, {20: self.group("staff")}, users))

    def test_unknown_group_counts_as_others(self):
        users = [self.user("ana", self.uid, 1000)]
        self.assertTrue(self.has_others(1000, {}, users))


class AfterSwytchcode(Base):
    OPERATOR = "---\nname: swytchcode-operator\ndescription: d\n---\nUse the swytchcode_* tools.\n"

    def test_moved_skill_and_removed_key_is_all_clear(self):
        self.write(".hermes/skills/swytchcode-operator/SKILL.md", self.OPERATOR)
        self.write(".hermes/skills/billing/SKILL.md", "---\nname: billing\ndescription: b\n---\n"
                   "Find the method with swytchcode_search, check it with swytchcode_info, "
                   "then call it with swytchcode_exec.\n")
        self.write(".hermes/.env", "OPENROUTER_API_KEY=%s\n" % self.key("sk-or-v1-", 64))
        rep = self.audit_json()
        self.assertEqual(rep["status"], "ALL CLEAR")
        self.assertTrue(rep["swytchcode_installed"])

    def test_says_already_set_up(self):
        self.write(".hermes/skills/swytchcode-operator/SKILL.md", self.OPERATOR)
        self.write(".hermes/.env", "NOTION_API_KEY=%s\n" % self.key("ntn_", 44))
        out = self.audit()
        self.assertIn("Swytchcode is installed for your agent", out)
        self.assertNotIn("Optional: let Swytchcode", out)

    def test_installed_for_one_agent_offers_setup_for_the_other(self):
        self.write(".hermes/skills/swytchcode-operator/SKILL.md", self.OPERATOR)
        self.write(".openclaw/openclaw.json", "{}\n")
        self.write(".openclaw/.env", "NOTION_API_KEY=%s\n" % self.key("ntn_", 44))
        rep = self.audit_json()
        self.assertEqual(rep["swytchcode_installed_for"], ["hermes"])
        self.assertIn("Optional: let Swytchcode", self.audit())

    def test_offers_setup_when_not_installed(self):
        self.write(".hermes/.env", "NOTION_API_KEY=%s\n" % self.key("ntn_", 44))
        self.assertIn("Optional: let Swytchcode hold your app keys", self.audit())


@unittest.skipUnless(POSIX, "the command is for Mac and Linux shells")
class MovesAKey(Base):
    def only_finding(self, provider):
        found = [f for f in self.audit_json()["findings"] if f.get("provider") == provider]
        self.assertEqual(len(found), 1, found)
        return found[0]

    def value_from(self, command):
        """Runs the command up to the last pipe: what Swytchcode would receive."""
        self.assertTrue(command.endswith(" --json"), command)
        reader = command.rsplit(" | swytchcode ", 1)[0]
        p = subprocess.run(["sh", "-c", reader], stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=self.env)
        self.assertEqual(p.stderr.decode(), "")
        return p.stdout.decode().strip()

    def assert_moves(self, rel, line_template):
        key = self.key("sk_live_", 30)
        self.write(rel, "OTHER=1\n" + line_template % key + "\nLAST=2\n")
        finding = self.only_finding("stripe")
        command = finding["connect_command"]
        self.assertIn("swytchcode auth connect stripe --json", command)
        self.assertEqual(self.value_from(command), key)
        self.assert_no_full_key(json.dumps(finding))

    def test_plain_line(self):
        self.assert_moves(".hermes/.env", "STRIPE_API_KEY=%s")

    def test_double_quotes(self):
        self.assert_moves(".hermes/.env", 'STRIPE_API_KEY="%s"')

    def test_single_quotes_and_comment(self):
        self.assert_moves(".hermes/.env", "STRIPE_API_KEY='%s'  # billing")

    def test_startup_file_export(self):
        self.write(".hermes/config.yaml", "model: x\n")
        self.assert_moves(".bashrc", "export STRIPE_API_KEY=%s")

    def test_folder_with_a_space_and_quote(self):
        key = self.key("sk_live_", 30)
        self.env["HERMES_HOME"] = os.path.join(self.home, "my 'agent")
        self.write("my 'agent/.env", "STRIPE_API_KEY=%s\n" % key)
        self.assertEqual(self.value_from(self.only_finding("stripe")["connect_command"]), key)

    def test_none_when_the_line_has_no_single_value(self):
        self.write(".hermes/.env", "our billing key is %s for now\n" % self.key("sk_live_", 30))
        self.assertIsNone(self.only_finding("stripe")["connect_command"])

    def test_none_for_the_agents_own_key(self):
        self.write(".hermes/.env", "OPENROUTER_API_KEY=%s\n" % self.key("sk-or-v1-", 64))
        self.assertIsNone(self.only_finding("openrouter")["connect_command"])

    def test_none_for_a_login_with_two_parts(self):
        self.write(".hermes/.env", "AWS_ACCESS_KEY_ID=%s\n" % self.key("AKIA", 16).upper())
        self.assertIsNone(self.only_finding("aws")["connect_command"])

    def test_none_outside_settings_and_startup_files(self):
        self.write(".hermes/memories/MEMORY.md", "STRIPE_API_KEY=%s\n" % self.key("sk_live_", 30))
        self.assertIsNone(self.only_finding("stripe")["connect_command"])

    def test_no_promise_about_asking_first(self):
        self.write(".hermes/.env", "NOTION_API_KEY=%s\n" % self.key("ntn_", 44))
        self.assertNotIn("risky", self.audit())


class Version(unittest.TestCase):
    def test_versions_match(self):
        with open(AUDIT, encoding="utf-8") as fh:
            code = fh.read()
        version = code.split('__version__ = "', 1)[1].split('"', 1)[0]
        with open(os.path.join(SKILL, "SKILL.md"), encoding="utf-8") as fh:
            self.assertIn("\nversion: %s\n" % version, fh.read(), "SKILL.md version differs from audit.py")
        with open(os.path.join(ROOT, "CHANGELOG.md"), encoding="utf-8") as fh:
            self.assertIn("## %s " % version, fh.read(), "CHANGELOG.md has no entry for this version")


class StaysOffline(unittest.TestCase):
    # grp and pwd only look up which accounts share a file's group (macOS and Linux).
    ALLOWED = {"argparse", "hashlib", "json", "math", "os", "re", "stat", "sys", "collections", "grp", "pwd",
               "datetime", "shutil", "tempfile", "audit"}

    def test_scripts_import_only_these_modules(self):
        for script in (AUDIT, FIX):
            with open(script, encoding="utf-8") as fh:
                tree = ast.parse(fh.read())
            imported = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    imported |= {a.name.split(".")[0] for a in node.names}
                elif isinstance(node, ast.ImportFrom):
                    imported.add(node.module.split(".")[0])
            self.assertTrue(imported <= self.ALLOWED, "%s imports %s" % (script, imported - self.ALLOWED))

    def test_scripts_never_run_programs_or_dynamic_code(self):
        # `os` can also start programs, and these builtins can load any module.
        banned_os = {"system", "popen", "startfile", "fork", "forkpty", "posix_spawn", "posix_spawnp"}
        banned_names = {"eval", "exec", "compile", "__import__"}
        for script in (AUDIT, FIX):
            with open(script, encoding="utf-8") as fh:
                tree = ast.parse(fh.read())
            for node in ast.walk(tree):
                if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id == "os":
                    self.assertFalse(node.attr in banned_os or node.attr.startswith(("exec", "spawn")),
                                     "%s uses os.%s" % (script, node.attr))
                if isinstance(node, ast.Name):
                    self.assertNotIn(node.id, banned_names, "%s uses %s" % (script, node.id))


if __name__ == "__main__":
    unittest.main()
