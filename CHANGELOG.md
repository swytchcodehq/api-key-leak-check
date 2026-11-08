# Changelog

## Unreleased

- Keys in the agent's memory now say they're sent to the AI provider with every message, for the files Hermes and OpenClaw put into every prompt. Other memory notes say "memory notes", not "chat history".
- On Ubuntu and most Linux systems, files readable only by your own private group are no longer reported as open to other accounts. Any other group, or a file owned by another account, still is.
- When Swytchcode is installed for the agent with the finding, the check offers to move app keys into it instead of offering to set it up. With two agents, each is checked on its own.
- Before a key is replaced, the agent asks where the new key should go: back in its settings, or in Swytchcode. The old key is deleted only once the new one works.
- Moving to Swytchcode uses a new key, removes the old copies and restarts the agent before checking the connection, and deletes the old key at the app only after the check passes. An old copy left in place would be used instead and make the check meaningless.
- Function names in skill code like `refresh_token_from_store` are no longer mistaken for keys. In settings, a password made of words is still found.
- The skill says plainly when the user asks about a file the check doesn't cover.
- Recent chats of a running Hermes are checked too: keys in `state.db-wal`, where new messages wait before SQLite moves them into `state.db`, were missed.
- The skill tells the agent never to search for keys on its own, and its description starts with the words people use.
- README: which model to use, and preloading the skill in Hermes.
- More tests (47): chat database, PowerShell profile, Markdown report, group access and the group lookup itself, after moving to Swytchcode, matching version numbers.

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
