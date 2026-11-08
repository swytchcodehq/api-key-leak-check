# API Key Leak Check for OpenClaw and Hermes

[![tests](https://github.com/swytchcodehq/api-key-leak-check/actions/workflows/test.yml/badge.svg)](https://github.com/swytchcodehq/api-key-leak-check/actions/workflows/test.yml)

**Is your AI agent leaking your API keys?** A free, read-only security check for [OpenClaw](https://openclaw.ai) and [Hermes](https://hermes-agent.nousresearch.com) agents. By [Swytchcode](https://swytchcode.com).

Ask your agent: *"Is my setup leaking any keys?"*

```
SECURITY CHECK: ACTION NEEDED

Your Stripe key is in your agent's memory, which is sent to your AI provider
with every message. Anyone who gets a copy of your agent's folder, including
malware, can use it to charge cards, issue refunds and see your customers.

What we found:
1. URGENT: Your Stripe key is in your agent's memory, which is sent to your AI
   provider with every message.
2. 1 file holding your keys can be opened by other accounts on this computer.

What you can do:
1. Clean up: remove the stray copies of your keys and lock your files. Your
   agent can do this for you, one step at a time.
2. Replace the exposed keys: make new ones at Stripe and turn off the old ones.
   This takes a few minutes each, on their websites.
3. Optional: let Swytchcode hold your app keys (Stripe), so your agent never
   has them and asks you before risky actions.

Say "show me the details" to see where each one is.

Nothing was changed. No key was shown or sent anywhere.
```

Ask for the details and it shows where each problem is and how to fix it. Ask it to clean up and it tells you exactly what will change, then waits for your yes.

## What it checks

- **Memory and chat history:** the agent's memory notes, saved chats and logs
- **Skills:** API keys written inside a skill, skills that print keys into the chat, skills that use your app keys directly
- **Settings:** keys saved as plain text, and files with keys that other accounts on the computer can open
- **Old backups:** backup and snapshot copies that still hold keys
- **Terminal startup files:** zsh, bash, fish and PowerShell profiles

It recognises keys for Stripe, GitHub, GitLab, Slack, AWS, Google, OpenAI, Anthropic, OpenRouter, SendGrid, Resend, Notion, Hugging Face and Telegram, plus any secret saved under a name like `API_KEY`, `TOKEN` or `SECRET`.

## Safe by design

- **The check only reads.** No network calls. A key is never shown, only its first 4 characters.
- **Fixes need your yes.** The agent shows what will change and waits. It never makes backup copies of your keys.
- **Your agent's own keys stay put.** It needs them to run, so the check only makes sure they're locked.
- **Nothing to install.** Python 3.9 or newer, standard library only. Tested on macOS, Linux and Windows on every change.
- **Read the code.** It's two short scripts: [`audit.py`](skills/api-key-leak-check/scripts/audit.py) finds problems, [`fix.py`](skills/api-key-leak-check/scripts/fix.py) fixes one item at a time after you say yes.
- **Passes Hermes's install check.** Hermes scans every skill it installs from GitHub and rates this one safe.

## Verify it yourself

You don't have to take our word for it. These take a few seconds.

**It can't send anything anywhere.** List everything the scripts import:

```
grep -hE "^(import|from) " skills/api-key-leak-check/scripts/*.py | sort -u
```

On Windows (PowerShell): `Select-String -Path skills\api-key-leak-check\scripts\*.py -Pattern '^(import|from) '`

You'll see only Python's own file and text modules (`os`, `re`, `json`, `hashlib` and so on), plus `audit`, which is the other script. There's no `socket`, `urllib`, `http`, `requests` or `subprocess`. The tests also check that the scripts never use `os.system`, `eval` or the other ways Python can run a program or load hidden code. Together that means the scripts can't reach the internet or start anything else. Both checks run on every change.

**It finds keys and never prints them.** Run the tests. They build a fake agent, plant fake keys, and check that each one is found and that no full key appears in any output:

```
python3 -m unittest discover -s tests -v
```

## Install

### Hermes

In a Hermes chat:
```
/skills install swytchcodehq/api-key-leak-check/api-key-leak-check
```
Or in a terminal: `hermes skills install swytchcodehq/api-key-leak-check/api-key-leak-check`

### OpenClaw

macOS / Linux:
```
git clone https://github.com/swytchcodehq/api-key-leak-check ~/api-key-leak-check
cp -R ~/api-key-leak-check/skills/api-key-leak-check ~/.openclaw/skills/
```

Windows (PowerShell):
```
git clone https://github.com/swytchcodehq/api-key-leak-check $HOME\api-key-leak-check
Copy-Item -Recurse $HOME\api-key-leak-check\skills\api-key-leak-check $HOME\.openclaw\skills\
```

### With the skills command (skills.sh)

```
npx skills add swytchcodehq/api-key-leak-check
```
It asks which agents to install it for. The check itself looks at OpenClaw and Hermes only.

### Both agents from one copy

Clone once and point both agents at the `skills` folder. `git pull` then updates both.

```
git clone https://github.com/swytchcodehq/api-key-leak-check ~/api-key-leak-check
```

- OpenClaw: `openclaw config set skills.load.extraDirs '["~/api-key-leak-check/skills"]' --strict-json`
- Hermes: add this to `~/.hermes/config.yaml`:
  ```yaml
  skills:
    external_dirs:
      - ~/api-key-leak-check/skills
  ```

Both pick up the skill on the next message. No restart needed.

## Which model to use

Use a capable model, like the one you'd use for everyday work. In our tests, GPT-5 class models loaded the skill, ran the check and showed the result exactly as written.

Small or free models may ignore the skill and try to search for keys on their own. One did in our tests, and printed a real token into the chat. Loading the skill or asking for it by name makes that less likely, but no skill can force a model to follow it:

- Hermes: start the chat with the skill loaded: `hermes chat -s api-key-leak-check`
- Any agent: ask for it by name: *"Use the api-key-leak-check skill. Am I leaking any keys?"*

The safest way, with any model, is to run the check yourself (below). It works the same without an agent, and no key can end up in a chat.

## Run it without an agent

```
python3 skills/api-key-leak-check/scripts/audit.py              # summary
python3 skills/api-key-leak-check/scripts/audit.py --details    # where and how to fix
python3 skills/api-key-leak-check/scripts/audit.py --markdown ~/security-check.md
```

On Windows, use `python` or `py` if `python3` isn't found.

## Who makes this

[Swytchcode](https://swytchcode.com) makes this check. It's free, and it works fully without Swytchcode.

For app keys like Stripe, GitHub and Notion, the check offers Swytchcode once, as an optional last step: Swytchcode holds those keys for your agent, so the agent never has them, and asks you before anything risky. Your agent never installs or sets up Swytchcode unless you say yes, and doesn't bring it up again if you say no.

## Security and releases

- Found a problem? Please report it privately. See [SECURITY.md](SECURITY.md).
- Changes for each version are in [CHANGELOG.md](CHANGELOG.md). To use a specific version, clone it by tag, for example `git clone --branch v1.0.0 https://github.com/swytchcodehq/api-key-leak-check`.
- MIT licensed. See [LICENSE](LICENSE).
