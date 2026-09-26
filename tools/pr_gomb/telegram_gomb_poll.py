#!/usr/bin/env python3
"""telegram_gomb_poll — fetching the Telegram INLINE BUTTON replies (callback_query) into an append-only ledger.

This file decides NOTHING: it writes every button press as a line into `valaszok.jsonl` (update_id, from_id, data,
callback_query_id, ts), acknowledges the button (answerCallbackQuery, so the phone does not keep spinning), and advances the getUpdates
offset. The decision and the merge are done by `pr_gomb.py feldolgoz` — a separate process, through a file, never a pipe.

If you already run your own Telegram poller (with the same bot token), do NOT run this one beside it (the getUpdates offset
is shared): the same 5 lines must be added to that one — see the README section "Existing poller".

Setup: the same config.json as pr_gomb.py's (telegram_bot_token_file, disabled_marker). Cron: every minute, under flock.
"""
import json
import os
import sys
import time
import urllib.parse
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
CONFIG_F = os.environ.get("PR_GOMB_CONFIG") or os.path.join(HERE, "config.json")
VALASZOK = os.path.join(HERE, "valaszok.jsonl")
OFFSET_F = os.path.join(HERE, ".telegram_offset")


def _read(p):
    return open(p, encoding="utf-8").read().strip()


def _tg(token, method, params):
    data = urllib.parse.urlencode({k: (json.dumps(v) if isinstance(v, (dict, list)) else v)
                                   for k, v in params.items()}).encode()
    with urllib.request.urlopen("https://api.telegram.org/bot%s/%s" % (token, method), data=data, timeout=40) as r:
        return json.load(r)


def main():
    with open(CONFIG_F, encoding="utf-8") as f:
        cfg = json.load(f)
    marker = cfg.get("disabled_marker")
    if marker and os.path.exists(marker):
        return 0                                                # disabled by a file: does not ask, does not write
    token = _read(cfg["telegram_bot_token_file"])
    off = int(_read(OFFSET_F) or "0") if os.path.exists(OFFSET_F) else 0
    res = _tg(token, "getUpdates", {"offset": off, "timeout": 20, "allowed_updates": ["callback_query"]})
    if not res.get("ok"):
        print("telegram_gomb_poll: getUpdates not ok: %s" % res)
        return 1
    last = off
    for u in res.get("result") or []:
        uid = int(u["update_id"])
        last = max(last, uid + 1)
        cq = u.get("callback_query")
        if not cq:
            continue
        with open(VALASZOK, "a", encoding="utf-8") as f:
            f.write(json.dumps({"update_id": uid, "from_id": (cq.get("from") or {}).get("id"),
                                "data": cq.get("data"), "callback_query_id": cq.get("id"),
                                "ts": int(time.time())}, ensure_ascii=False) + "\n")
        try:
            _tg(token, "answerCallbackQuery", {"callback_query_id": cq.get("id"), "text": "Received, processing."})
        except Exception as e:                                  # the acknowledgement is a convenience layer; the ledger already has it
            print("telegram_gomb_poll: answerCallbackQuery error: %s" % e)
    if last != off:
        with open(OFFSET_F, "w", encoding="utf-8") as f:
            f.write(str(last))
    return 0


if __name__ == "__main__":
    sys.exit(main())
