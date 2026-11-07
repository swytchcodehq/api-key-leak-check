#!/usr/bin/env python3
"""Fix problems found by audit.py, one finding at a time, by id.

The agent runs this only after the person said yes to that exact fix. It
re-runs the audit, so it only ever touches what the audit finds right now.
It never prints a key and never writes a backup copy (a backup is another
leak).

  fix.py --dry-run ID [ID ...]   say what would change, change nothing
  fix.py ID [ID ...]             make the change

What each fix does:
  lock         only you can open the file (macOS and Linux)
  delete       delete an old backup copy that holds keys
  remove-line  remove the line holding the key (memory notes, .env, shell startup files)
  blank        remove just the key and keep the rest of the file (settings, chat logs)

Keys the agent needs to run, keys in databases, and keys inside skills are
never changed here.

Python 3.9+ standard library only. Works on macOS, Linux and Windows.
"""

import argparse
import os
import shutil
import stat
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import audit as A  # noqa: E402


def within(path, roots):
    real = os.path.realpath(path)
    for r in roots:
        r = os.path.realpath(r)
        if real != r and real.startswith(r.rstrip(os.sep) + os.sep):
            return True
    return False


def write_atomic(path, data):
    st = os.stat(path)
    d = os.path.dirname(path)
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".swy-fix-")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        if os.name != "nt":
            os.chmod(tmp, stat.S_IMODE(st.st_mode))
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def describe(f):
    if f["kind"] == "secret":
        return "your %s key" % A.nice(f["provider"]) if f["provider"] != "unknown" else "a key"
    return "this file"


def plan(f, roots):
    """Return (ok, sentence). ok False means it won't be done."""
    a = f["action"]
    where = f["path"] + (" (line %d)" % f["line"] if f["line"] else "")
    shell_file = f["area"] == "shell"
    if not shell_file and not within(f["abspath"], roots):
        return False, "Won't change %s: it's outside your agent's folder." % f["path"]
    if a == "lock":
        if os.name == "nt":
            return False, "Locking files isn't needed on Windows."
        return True, "Lock %s so only you can open it." % f["path"]
    if a == "delete":
        return True, "Delete the old backup copy %s. You won't be able to restore your agent from this copy." % f["path"]
    if a == "remove-line":
        return True, "Remove line %d from %s (it holds %s). Nothing else in the file changes." % (f["line"], f["path"], describe(f))
    if a == "blank":
        return True, "Remove %s from %s. The rest of the file stays as it is." % (describe(f), where)
    if a == "none":
        return False, "Won't change %s: your agent needs this key to run." % f["path"]
    if a == "replace-skill":
        return False, "Won't change the skill here. Turn it off or rewrite it instead (see move-to-swytchcode.md)."
    if a == "chat-db":
        return False, ("Can't remove a key from %s: it's inside your agent's saved chats. "
                       "Delete your old chats in the agent instead." % f["path"])
    return False, "Can't fix %s automatically. It has to be removed by hand." % where


def apply(f, raw):
    path = f["abspath"]
    a = f["action"]
    if a == "lock":
        os.chmod(path, 0o700 if os.path.isdir(path) else 0o600)
        return
    if a == "delete":
        if os.path.isdir(path):
            shutil.rmtree(path)
        else:
            os.unlink(path)
        return
    with open(path, "rb") as fh:
        data = fh.read()
    secret = raw.encode("utf-8")
    if secret not in data:
        raise RuntimeError("the key is no longer in this file")
    if a == "remove-line":
        lines = data.splitlines(True)
        idx = f["line"] - 1
        if not (0 <= idx < len(lines) and secret in lines[idx]):
            # An earlier fix in this run removed a line above it; find the
            # line by the key itself, but only if there's exactly one.
            hits = [n for n, l in enumerate(lines) if secret in l]
            if len(hits) != 1:
                raise RuntimeError("the file changed since the check; run the check again")
            idx = hits[0]
        del lines[idx]
        write_atomic(path, b"".join(lines))
    elif a == "blank":
        write_atomic(path, data.replace(secret, b""))
    else:
        raise RuntimeError("not something this can fix")


def main():
    ap = argparse.ArgumentParser(description="Fix problems found by audit.py, by id.")
    ap.add_argument("ids", nargs="+", help="finding ids from audit.py --json")
    ap.add_argument("--dry-run", action="store_true", help="say what would change, change nothing")
    ap.add_argument("--platform", choices=["auto", "openclaw", "hermes"], default="auto")
    ap.add_argument("--home")
    args = ap.parse_args()
    A.ascii_safe(sys.stdout)

    audit, targets = A.run_audit(args.platform, args.home)
    roots = [h for _, h in targets]
    by_id = {f["id"]: f for f in audit.findings}
    failed = 0
    for i in args.ids:
        f = by_id.get(i)
        if not f:
            print("%s: not found. It may already be fixed; run the check again." % i)
            failed += 1
            continue
        ok, sentence = plan(f, roots)
        if args.dry_run or not ok:
            print(("Will do: " if ok else "Skipped: ") + sentence)
            failed += 0 if ok else 1
            continue
        try:
            apply(f, audit.raw.get(i, ""))
            print("Done: " + sentence)
        except Exception as e:  # report in plain words, never the key
            print("Couldn't do it: %s (%s)." % (sentence, e))
            failed += 1
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
