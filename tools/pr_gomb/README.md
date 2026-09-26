# pr_gomb — a merge decision with a Telegram button (the human key in the KET_EMBER_KULCS rule)

**For whom:** an operator who needs a HUMAN key for PR merges on their own side — on Telegram, with one
click, in a way that the button bypasses NOTHING of GitHub's branch protection. On the Zynko side this has run since 2026-09-17
(with the operator's key); this package is the same, without secrets and personal identifiers, parameterized from a config file.

## What it does

1. `pr_gomb.py kerd <repo> <pr>` → a PR card goes to the operator's private chat with the bot:
   title, branch, **head SHA**, `mergeable_state`, the other party's review, and two buttons: **[MERGE ✅] [NO ❌]**.
   The request goes into the append-only `kerelmek.jsonl` (id, head SHA, message_id).
2. The button press arrives at the bot as a `callback_query`. `telegram_gomb_poll.py` (or your own poller) writes it into
   `valaszok.jsonl` (from_id, data, ts), and acknowledges it. **The poller does not decide.**
3. `pr_gomb.py feldolgoz` (cron, every minute) goes through the new replies:
   * the click was not the operator's → recorded, ignored;
   * `NO` → recorded, a stated rejection (a third state, not silence), feedback on Telegram;
   * `MERGE` → fetches the PR again; if the **head changed** since the request → does NOT run it, says so; otherwise
     `PUT /pulls/{n}/merge` in **merge-commit** mode, bound to the `sha` at request time. If GitHub refuses
     (a missing required review, a red check, a protected branch) → "Did NOT run: <reason>" — the button **does not bypass** the platform.
   * every decision goes into `dontesek.jsonl` (append-only). A request can be decided once.

## What it does NOT do (stated)

* It does not give a review/approve (the PR's author cannot approve their own on GitHub). The button = the merge itself.
* It does not squash, does not rebase: the base-pin anchors point to the merge commit's SHA.
* It does not bypass a head change: the decision is bound to the head AT REQUEST TIME, a new head needs a new request.
* It deletes nothing: all three ledgers are append-only.
* It does not write a token into the log.

## Installation (5 minutes)

1. Bot: `@BotFather` → new bot → token → into a file (`telegram_bot_token_file`, 0600). Send the bot a message from your own
   account, and read out the `chat.id` + your own `from.id` (e.g. `getUpdates`): that is the content of `telegram_chat_id_file`
   and the `owner_id`.
2. GitHub: a fine-grained or classic token with `repo` rights on the target repos → into a file (`github_token_file`, 0600). The token's
   owner should have **merge rights**, but branch protection (a required review from the other party) applies to them too — that is the point.
3. `cp config.example.json config.json`, fill it in. `owner_id` = YOUR Telegram user id (integer).
4. A trial without sending: `python3 pr_gomb.py kerd <repo> <pr> --proba` — prints the card, does not send, does not write the ledger.
5. Cron: the two lines of `crontab.example` (with the paths rewritten). If you already have your own poller with the same bot token,
   see below, and add only line 2.

## Existing poller

The `getUpdates` offset is shared per bot, so ONE poller should run per bot token. If you already have one, put this in it
(the same as the core of `telegram_gomb_poll.py`):

```python
cq = u.get("callback_query")
if cq:
    with open(VALASZOK, "a", encoding="utf-8") as f:
        f.write(json.dumps({"update_id": uid, "from_id": (cq.get("from") or {}).get("id"),
                            "data": cq.get("data"), "callback_query_id": cq.get("id"), "ts": int(time.time())}) + "\n")
    _tg("answerCallbackQuery", {"callback_query_id": cq.get("id"), "text": "Received, processing."})
```

## Switching off

With a file, not with code: create the `disabled_marker` file → the bot does not send, the poller does not ask; `rm` = back on.

## Why this way (lessons from the Zynko side)

* **Two humans' keys.** The two-key rule assigned to agents gives zero keys (both agents refer to the human).
  So one key is the operator's button, the other is the other party's GitHub review — the platform enforces it.
* **A decision bound to the head.** A "yes" only applies to the byte sequence the operator saw.
* **A third state.** "NO" and "did not run, because…" are recorded separately; silence is not a decision.
* **Append-only.** The ledger is an audit, not a state: afterwards it shows who decided what when, and what came of it.
