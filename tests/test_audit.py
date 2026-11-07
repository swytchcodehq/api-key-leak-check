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


class StaysOffline(unittest.TestCase):
    ALLOWED = {"argparse", "hashlib", "json", "math", "os", "re", "stat", "sys", "collections",
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
