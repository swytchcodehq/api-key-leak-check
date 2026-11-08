# Changelog

## Unreleased

- Keys in the agent's memory now say they're sent to the AI provider with every message (memory goes into every prompt in Hermes and OpenClaw).
- On Ubuntu and most Linux systems, files readable only by your own group are no longer reported as open to other accounts.
- When Swytchcode is already set up, the check offers to move app keys into it instead of offering to set it up.
- After a key is replaced, the agent asks where the new key should go: back in its settings, or in Swytchcode.
- Moving to Swytchcode now checks the connection works before removing the old key, so nothing breaks if connecting fails.
- Setting names like `refresh_token_from_store` are no longer mistaken for keys.
- The skill tells the agent never to search for keys on its own, and its description starts with the words people use.
- README: which model to use, and preloading the skill in Hermes.
- More tests: chat database, PowerShell profile, Markdown report, group access, after moving to Swytchcode, matching version numbers.

## 1.0.1 (2026-11-07)

- Security reports by email now go to hello@swytchcode.com, with a subject starting "Security:".

## 1.0.0 (2026-11-07)

First release.

- Checks OpenClaw and Hermes agents for API keys in memory and chat history, skills, settings, old backups and terminal startup files.
- Explains the result in plain words, with details on request.
- Says which agent each problem is in, when both are installed.
- `fix.py` fixes one item at a time after the user says yes: removes a key, locks a file or deletes an old backup. It never touches the agent's own keys.
- Optional step to move app keys to Swytchcode, only with the user's yes.
- Tested on macOS, Linux and Windows, Python 3.9 and 3.13.
