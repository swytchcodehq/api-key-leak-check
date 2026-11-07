# Security policy

This tool reads files that hold people's API keys, so we take reports about it seriously.

## Reporting a problem

Please report privately. Don't open a public issue.

- **On GitHub:** use "Report a vulnerability" on the repository's Security tab.
- **By email:** security@swytchcode.com

Tell us what you found, how to reproduce it, and which version you used (`python3 skills/api-key-leak-check/scripts/audit.py --version`). Please don't include real keys in your report. If you need an example, make a fake one.

We'll reply within 3 working days, and keep you updated until it's fixed. We're happy to credit you in the changelog if you'd like.

## What counts

Anything that breaks these promises:

- The check only reads. It never changes a file.
- Nothing is sent over the network.
- A full key is never printed, in any output mode or report.
- `fix.py` only changes the exact item it was given, only inside the agent's folder or the terminal startup files, and never makes a backup copy of a key.

Also in scope: a way to make the agent show a key in the chat while using this skill, or keys the check misses that it claims to find.

## Supported versions

Only the latest release gets fixes.
