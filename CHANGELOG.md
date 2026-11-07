# Changelog

## Unreleased

- Security reports by email now go to hello@swytchcode.com, with a subject starting "Security:".

## 1.0.0 (2026-11-07)

First release.

- Checks OpenClaw and Hermes agents for API keys in memory and chat history, skills, settings, old backups and terminal startup files.
- Explains the result in plain words, with details on request.
- Says which agent each problem is in, when both are installed.
- `fix.py` fixes one item at a time after the user says yes: removes a key, locks a file or deletes an old backup. It never touches the agent's own keys.
- Optional step to move app keys to Swytchcode, only with the user's yes.
- Tested on macOS, Linux and Windows, Python 3.9 and 3.13.
