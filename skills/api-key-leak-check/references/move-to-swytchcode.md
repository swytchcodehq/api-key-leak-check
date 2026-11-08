# Moving app keys and skills to Swytchcode

Use this only after the user said yes to Swytchcode. That one yes covers everything here: you do the work, and you only stop where a step says the user has to do something. Say in one plain sentence what you're doing as you go.

Swytchcode only takes app keys (Stripe, GitHub, Notion and so on). The agent's own keys (its AI model, chat bot and login) stay where they are.

Never open a file that holds a key, and never put a key in a command you wrote yourself. Run `connect_command` exactly as `audit.py --json` gives it: it hands the key straight to Swytchcode, so the key never appears in this chat.

## 1. Say what will happen

Run `audit.py --json`. Take the findings for app keys: `provider` is the app, it isn't `unknown`, and `own_key` isn't true. If some say `unknown`, run `--details` and ask the user whether any of them is an app key they want moved, by the setting's name.

Tell the user in one message which apps you'll move and that the old copies get removed from the agent's files. Also name any skill that uses those keys (`skills` in `audit.py --json`, where `swytchcode_can_replace` is true): it stops working once the old key is gone, until step 8. If they object to something, leave that app out.

## 2. Set up Swytchcode (once)

First find the project folder: the nearest folder with a `.swytchcode/tooling.json`, starting from the folder you're working in and going up, or `~/swytchcode` if it has one. The steps below call it `<project>`. If you create it here, it's `~/swytchcode`.

Skip to step 3 only if `swytchcode whoami` says they're signed in and you found a project folder. Having the `swytchcode_*` tools isn't enough, because the steps below also run the `swytchcode` command. If you have the tools but your terminal can't find that command (for example, it runs in a container), stop and tell the user: "My terminal can't reach Swytchcode, so I can't move your keys from here. Nothing has changed. Swytchcode needs to be installed where my terminal runs." If there's a project folder and they just aren't signed in, do only item 4.

1. **Install.** Run `swytchcode --version`. If it isn't found, run `npm install -g swytchcode`. If there's no `npm`, ask the user to follow https://cli.swytchcode.com and tell you when it's finished. Then run `swytchcode --version` again. If it still isn't found, stop and leave their keys where they are.
2. **Create the project and connect it to the agent.** Use `hermes` or `openclaw` for your agent:
   ```
   swytchcode init --operator --mode=production --non-interactive --editor=hermes --project ~/swytchcode
   ```
   On Windows, use `$HOME\swytchcode` for the folder. If the output has a line that registers the MCP server (like `hermes mcp add swytchcode ...`), run exactly that line. Don't copy the optional lock-down steps it also prints.
3. **Turn off the approval rule.** Setup adds a rule that holds every call that changes something until someone approves it in Slack or Telegram, which the free plan doesn't include. Without this step, your calls that change something would be refused:
   ```
   cd ~/swytchcode && swytchcode policy remove agent-writes-need-approval
   ```
4. **Sign in (the user does this).** Run `swytchcode login` and keep it running. Send the user the link it prints: "Open this link and sign in. If you don't have an account, you can make a free one there." If you can't see its output while it runs, ask them to run `swytchcode login` in their own terminal. Wait until it's finished.

## 3. Move the keys

Do this for one app at a time, from `<project>`.

1. Get the app: `swytchcode get <app> --non-interactive`. If it isn't available, tell the user "Swytchcode doesn't support [app] yet, so that key stays where it is, locked." Skip this app.
2. Run `audit.py --json` again, so the line numbers are current.
3. If the finding has a `connect_command`, run `cd <project> && <connect_command>`, with the command exactly as given. If the output has a link, send it to the user and wait until they've signed in.
4. If it has no `connect_command`, the user has to enter it. Ask them to run `cd <project> && swytchcode auth connect <app>` in their own terminal and paste the key there, never into this chat. For apps like Gmail or Slack, this is a sign-in page in their browser.
5. Run `swytchcode auth status` and check the app is listed. **If it isn't, stop for this app and leave its old copies alone.**

If the same key is in several places, connect it once.

## 4. Remove the old copies

Only for apps that passed step 3. An old copy left in the agent's files is still exposed, and it's used instead of the one Swytchcode holds, so the check in step 6 could pass with the old key and prove nothing.

1. Run `fix.py --dry-run <ids>` for every finding for those apps, and tell the user briefly what it will remove.
2. Run `fix.py <ids>`.
3. If an item can't be fixed by `fix.py`, tell the user what to do in plain words. For the agent's own settings, give them the exact command to copy, and wait until they say it's done.
4. Run `audit.py --json` again. If a copy of a moved key is still there, tell the user which one and don't go on until it's gone. A key written inside a skill is the exception: step 8 deals with it, so carry on.

If you have to stop at any point after this, tell the user which skills have stopped working and that they can ask you to finish the move.

## 5. Restart the agent (the user does this)

The agent can't restart itself, and it only loads the Swytchcode tools and drops the old keys when it starts.

- Hermes: "Close Hermes and start it again with `hermes --continue`, so we carry on where we left off."
- OpenClaw: "Paste `openclaw gateway restart` in the terminal, then ask me to carry on."

If a key was in a terminal startup file, they also open a new terminal before starting the agent. With OpenClaw, if they started the gateway by hand in a terminal, `openclaw gateway restart` can keep the old key: ask them to stop it in that terminal (Ctrl+C), open a new terminal and run `openclaw gateway` there.

## 6. Check it works

For each app you moved, make one call through Swytchcode that only reads something: `swytchcode_info`, then `swytchcode_exec` (for example, list one customer, or get the signed-in user). Tell the user in one line per app: "Swytchcode is now holding your Stripe key, and it works."

If one fails, tell them which app and what went wrong, and ask them to connect that key again in their own terminal (step 3, item 4). Don't put the key back in the agent's files.

## 7. Replace keys that really got out

If a moved key's finding has `rotate: true`, or the same key was also in memory, chat history or a skill, moving it doesn't undo the leak. Ask the user to:

1. Make a new key on the app's website. The links are in `audit.py --details`.
2. Run `cd <project> && swytchcode auth connect <app>` in their own terminal and paste the new key there.
3. Tell you when it's done, so you can repeat the check in step 6.
4. Delete the old key on the app's website.

## 8. Replace the skills that used the key

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

If the skill had a key written inside it, that key must be replaced on the app's website (step 7), whichever fix the user picks. Turning a skill off leaves the key on disk, so before you rewrite the skill or after it's turned off, ask the user to delete the key from that file themselves (`audit.py --details` shows the file and line), or to delete the skill's folder if they don't need it.

## 9. Done

Run `audit.py` again and show the result. Tell the user: "Your [app] key is now held by Swytchcode, and your agent doesn't have it anymore. The free plan includes 1,000 live commands a month."
