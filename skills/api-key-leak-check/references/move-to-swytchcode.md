# Moving app keys and skills to Swytchcode

Use this only after the user said yes to Swytchcode. Go one app at a time. Before each step, say in one plain sentence what happens and who does it, and wait for a yes.

Swytchcode only takes app keys (Stripe, GitHub, Notion and so on). The agent's own keys (its AI model, chat bot and login) stay where they are.

## 1. Set up Swytchcode (once)

If you have the `swytchcode_*` tools, it's set up already: go to step 2.

If not, ask the user to install it. Don't install it yourself.

1. **Install.** If they have Node (every OpenClaw user does), they open a terminal and paste:
   ```
   npm install -g swytchcode
   ```
   Otherwise: "Go to https://cli.swytchcode.com and follow the install steps for your computer."
2. **Connect it to the agent.** In the terminal, they paste the line for their computer:
   - Mac or Linux: `swytchcode init --operator --editor=openclaw --project ~/swytchcode`
   - Windows (PowerShell): `swytchcode init --operator --editor=openclaw --project $HOME\swytchcode`

   For Hermes, use `--editor=hermes` instead of `--editor=openclaw`.

Tell them: "It may ask you to sign in or answer a few questions. Follow what it says on screen, then tell me when it's done." Don't run these yourself. The Swytchcode tools work from your next message.

## 2. Check Swytchcode has the app

Call `swytchcode_search` with the app's name. If it isn't there, tell the user: "Swytchcode doesn't support [app] yet, so let's just replace that key and keep it locked." Then skip this app.

## 3. Connect the app

Call `swytchcode_connect` with the app. Send the user the result's `action.message`, with its `action.url` or `action.command`, exactly as given. Then wait for them to say it's done.

- For apps like Gmail or Slack, that's a sign-in page in their browser.
- For apps that use a key, the user pastes the key into **their terminal** when asked. Never into this chat.

Suggest they make a **new** key on the app's website for this, because the old one was exposed.

## 4. Remove the old copies

**This step is required.** If an old copy of the key is left in the agent's files or the terminal startup files, it's still exposed, and it's used instead of the one Swytchcode holds.

1. Run `audit.py --json` and find every finding for this app's key (`provider` is the app).
2. Run `fix.py --dry-run <ids>`, tell the user what it will do, and after their yes, run `fix.py <ids>`.
3. If an item can't be fixed by `fix.py`, tell the user what to do in plain words. For the agent's own settings, give them the exact command to copy.
4. After a change to the agent's settings or `.env` file, the agent has to restart. OpenClaw: `openclaw gateway restart`. Hermes: start a new chat.

## 5. Check it works

Make one call through Swytchcode that only reads something: `swytchcode_info`, then `swytchcode_exec` (for example, list one customer, or get the signed-in user). Tell the user the result in one line: "Done. Swytchcode is now holding your Stripe key, and it works."

If it fails, tell them what went wrong and stop. Never go back to the old key.

## 6. Turn off the old key

If they didn't make a new key in step 3, ask them to now: "Go to [link], make a new key and delete the old one." The links are in `audit.py --details`. Then connect the new key with `swytchcode_connect`.

## 7. Replace the skills that used the key

Find the skills that used this app (`skills` in `audit.py --json`, where `swytchcode_can_replace` is true). Those skills stop working once the old key is gone. For each one, pick the fix by its type, and ask before doing it:

| Skill | What to offer |
| --- | --- |
| Came with the agent (Hermes's built-in skills, OpenClaw's bundled skills) | **Turn it off.** Swytchcode handles that app now. Don't rewrite it: the agent's next update would put the old version back. |
| Only instructions (SKILL.md tells you to call the app, `has_scripts` is false) | **Turn it off**, or **rewrite it** so each step calls the `swytchcode_*` tools instead of the app. |
| Has scripts (`has_scripts` is true) | **Turn it off.** Scripts can't use the Swytchcode tools. If the user wants to keep it, rewrite only the SKILL.md steps that call the app so that you make those calls with `swytchcode_exec`, and leave the scripts for work that doesn't call the app. |

Turning a skill off (the user does this):
- OpenClaw: paste `openclaw config set skills.entries.<skill name>.enabled false --strict-json` in the terminal.
- Hermes: type `hermes skills config` in the terminal, turn the skill off in the list, and save.

Rewriting a skill (you do this, after a yes):
1. Tell the user which files change and what changes, in one or two sentences.
2. Replace each step that calls the app (`curl`, `requests`, `fetch`, an app's own tool) with: find the method with `swytchcode_search`, check its inputs with `swytchcode_info`, call it with `swytchcode_exec`.
3. Remove every mention of the key and the variable that held it.
4. Use your normal way of saving skills.

If the skill had a key written inside it, that key must be replaced on the app's website (step 6), whichever fix the user picks.

## 8. Done

Run `audit.py` again and show the result. Tell the user: "Your [app] key is now held by Swytchcode. Your agent doesn't have it anymore, and Swytchcode will ask you before anything risky."
