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

Tell them: "It may ask you to sign in or answer a few questions. Follow what it says on screen, then tell me when it's done." Don't run these yourself.

The agent loads the Swytchcode tools when it starts, so it has to start again:
- Hermes: "Close Hermes and start it again with `hermes --continue`, so we carry on where we left off."
- OpenClaw: "Paste `openclaw gateway restart` in the terminal, then ask me to carry on."

## 2. Check Swytchcode has the app

Call `swytchcode_search` with the app's name. If it isn't there, tell the user: "Swytchcode doesn't support [app] yet, so let's just replace that key and keep it locked." Then skip this app.

## 3. Connect the app

Call `swytchcode_connect` with the app. Send the user the result's `action.message`, with its `action.url` or `action.command`, exactly as given. Then wait for them to say it's done.

- For apps like Gmail or Slack, that's a sign-in page in their browser.
- For apps that use a key, the user pastes the key into **their terminal** when asked. Never into this chat.

Ask them to make a **new** key on the app's website and connect that one, because the old one was exposed. Tell them to keep the old key switched on for now: it's turned off in step 6, once Swytchcode's copy is proven to work. That way nothing stops working if a step goes wrong.

## 4. Remove the old copies

**This step is required, and it comes before the check in step 5.** An old copy left in the agent's files or the terminal startup files is still exposed. Worse, it's used instead of the one Swytchcode holds, so a check made while it's still there could pass with the old key and prove nothing.

1. Run `audit.py --json` and find every finding for this app's key (`provider` is the app).
2. Run `fix.py --dry-run <ids>`, tell the user what it will do, and after their yes, run `fix.py <ids>`.
3. If an item can't be fixed by `fix.py`, tell the user what to do in plain words. For the agent's own settings, give them the exact command to copy.
4. The agent has to start again so the old key is gone from it too. Hermes: "Close Hermes and start it again with `hermes --continue`." OpenClaw: "Paste `openclaw gateway restart` in the terminal." If a key was in a terminal startup file, they also open a new terminal before starting the agent.

## 5. Check it works

Make one call through Swytchcode that only reads something: `swytchcode_info`, then `swytchcode_exec` (for example, list one customer, or get the signed-in user). Now that the old copies are gone, this really uses the key Swytchcode holds. Tell the user the result in one line: "Done. Swytchcode is now holding your Stripe key, and it works."

If it fails, tell them what went wrong and connect the new key again with `swytchcode_connect` (step 3). Don't put the old key back in the agent's files. Their old key still works at the app until step 6, so nothing is lost while you fix it.

## 6. Turn off the old key

Only after step 5 worked. Ask them to delete the old key on the app's website: "Go to [link] and delete the old key. The new one in Swytchcode keeps working." The links are in `audit.py --details`.

If they connected the old key in step 3 instead of a new one, ask them to make a new key now, connect it with `swytchcode_connect`, check it again (step 5), and then delete the old one.

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
