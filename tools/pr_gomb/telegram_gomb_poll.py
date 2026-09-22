#!/usr/bin/env python3
"""telegram_gomb_poll — a Telegram INLINE GOMB válaszainak (callback_query) lekérése egy append-only könyvbe.

Ez a fájl NEM dönt semmiről: minden gombnyomást egy sorként a `valaszok.jsonl`-be ír (update_id, from_id, data,
callback_query_id, ts), a gombot nyugtázza (answerCallbackQuery, hogy a telefon ne pörögjön), és a getUpdates offsetjét
lépteti. A döntést és a merge-et a `pr_gomb.py feldolgoz` végzi — külön folyamat, fájlon át, soha csövön.

Ha már fut egy saját Telegram-poller (ugyanazzal a bot-tokennel), akkor NE ezt futtasd mellette (a getUpdates offset
közös): abba kell beleírni ugyanezt az 5 sort — lásd README „Meglévő poller".

Beállítás: ugyanaz a config.json, mint a pr_gomb.py-é (telegram_bot_token_file, disabled_marker). Cron: percenként, flock alatt.
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
        return 0                                                # kikapcsolva fájllal: nem kérdez, nem ír
    token = _read(cfg["telegram_bot_token_file"])
    off = int(_read(OFFSET_F) or "0") if os.path.exists(OFFSET_F) else 0
    res = _tg(token, "getUpdates", {"offset": off, "timeout": 20, "allowed_updates": ["callback_query"]})
    if not res.get("ok"):
        print("telegram_gomb_poll: getUpdates nem ok: %s" % res)
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
            _tg(token, "answerCallbackQuery", {"callback_query_id": cq.get("id"), "text": "Megkaptam, feldolgozom."})
        except Exception as e:                                  # a nyugta kényelmi réteg; a könyv már megvan
            print("telegram_gomb_poll: answerCallbackQuery hiba: %s" % e)
    if last != off:
        with open(OFFSET_F, "w", encoding="utf-8") as f:
            f.write(str(last))
    return 0


if __name__ == "__main__":
    sys.exit(main())
