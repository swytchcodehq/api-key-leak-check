# API Key Leak Check for OpenClaw and Hermes

**Is your AI agent leaking your API keys?** A free, read-only security check for [OpenClaw](https://openclaw.ai) and [Hermes](https://hermes-agent.nousresearch.com) agents. By [Swytchcode](https://swytchcode.com).

Ask your agent: *"Is my setup leaking any keys?"*

```
SECURITY CHECK: ACTION NEEDED

Your Stripe key is saved in your agent's memory or chat history. Anyone who gets
a copy of your agent's folder, including malware, can use it to charge cards,
issue refunds and see your customers.

What we found:
1. URGENT: Your Stripe key is saved in your agent's memory or chat history.
2. 2 files holding your keys can be opened by other accounts on this computer.
3. 1 skill uses your Notion key directly: notion.

What you can do:
1. Clean up: remove the stray copies of your keys and lock your files.
   Your agent can do this for you, one step at a time.
2. Replace the exposed keys: make new ones at Stripe and turn off the old ones.
3. Optional: let Swytchcode hold your app keys (Stripe and Notion), so your
   agent never has them and asks you before risky actions.

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
- **Nothing to install.** Python 3.6 or newer, standard library only. macOS, Linux and Windows.
- **Read the code.** It's two short scripts: [`audit.py`](skills/api-key-leak-check/scripts/audit.py) finds problems, [`fix.py`](skills/api-key-leak-check/scripts/fix.py) fixes one item at a time after you say yes.

## Install

### Hermes

In a Hermes chat:
```
/skills install swytchcodehq/api-key-leak-check/skills/api-key-leak-check
```
Or in a terminal: `hermes skills install swytchcodehq/api-key-leak-check/skills/api-key-leak-check`

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

## Run it without an agent

```
python3 skills/api-key-leak-check/scripts/audit.py              # summary
python3 skills/api-key-leak-check/scripts/audit.py --details    # where and how to fix
python3 skills/api-key-leak-check/scripts/audit.py --markdown ~/security-check.md
```

On Windows, use `python` or `py` if `python3` isn't found.

## About Swytchcode

For app keys like Stripe, GitHub and Notion, the check can offer to move them to [Swytchcode](https://swytchcode.com). Swytchcode holds them for your agent, so the agent never has them, and asks you before anything risky. It's optional: nothing is set up unless you say yes.
