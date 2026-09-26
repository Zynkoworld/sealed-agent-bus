#!/usr/bin/env python3
"""pr_gomb — merge approval with a Telegram button: the OPERATOR'S ONE KEY on their own side.

WHY: the two-key rule ended up with zero keys — both agents referred the decision to a human,
but the rule assigned both keys to agents. This package is the HUMAN key: a PR card on Telegram with two buttons
([MERGE ✅] [NO ❌]), and the click is the merge itself — or its stated omission.

WHAT IT DOES AND DOES NOT DO (stated):
  * the button = the MERGE ITSELF, which runs ONLY if the platform's other conditions hold (required approval present, the head
    has not changed); otherwise it STATES why not — it never bypasses branch protection;
  * the merge method is ALWAYS a merge commit (never squash/rebase: the base-pin anchors point to the merge commit's SHA);
  * the decision is bound to the head SHA AT REQUEST TIME: if the PR head has changed since, the button does not execute, it asks for a new request;
  * ONLY the operator's (OWNER_ID) click counts; every other sender is recorded, but ignored;
  * a request can be decided ONCE (idempotent); a second click gets an "already decided" reply;
  * every ledger is append-only (kerelmek / valaszok / dontesek.jsonl) — nothing is deleted;
  * the GitHub token and the bot token never go into output/logs.

Setup: `config.json` next to the file (see config.example.json) — or the `PR_GOMB_CONFIG` env with the file's path.
  {
    "github_org":     "Zynkoworld",                      # the repos' owner (org or user)
    "github_token_file": "~/.config/agentbus/github_token",          # repo-scope token, the file is 0600
    "telegram_bot_token_file": "~/.config/agentbus/telegram_bot_token",
    "telegram_chat_id_file":   "~/.config/agentbus/telegram_chat_operator",   # the operator's private chat with the bot
    "owner_id": 123456789,                               # the operator's Telegram user id (ONLY their click counts)
    "self_login": "Zynkoworld",                          # the PRs' author: its review is not "someone else's"
    "disabled_marker": "~/.config/agentbus/telegram_DISABLED" # if it exists, the bot does not send (switched off by a file, not by code)
  }

Usage:
  pr_gomb.py kerd <repo> <pr>          # request: PR card + [MERGE ✅] [NO ❌] buttons to the operator
  pr_gomb.py kerd <repo> <pr> --proba  # only shows what it would send (does not send, does not write the ledger)
  pr_gomb.py feldolgoz                 # execute the received button replies (from cron, every minute)
  pr_gomb.py allapot                   # pending requests

The button replies are written by `telegram_gomb_poll.py` into `valaszok.jsonl` (callback_query → line); that file decides NOTHING.
Cron (always through a file, never a pipe): see crontab.example.
"""
import hashlib
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
CONFIG_F = os.environ.get("PR_GOMB_CONFIG") or os.path.join(HERE, "config.json")
KERELMEK, VALASZOK, DONTESEK = (os.path.join(HERE, x) for x in ("kerelmek.jsonl", "valaszok.jsonl", "dontesek.jsonl"))
OFFSET_F = os.path.join(HERE, ".valaszok_offset")


def _path(p):
    """`~` may also appear in the config — the defaults deliberately point to the user's own directory, not to a
    particular machine's layout, so every path in the config is expanded here, in one place."""
    return os.path.expanduser(p) if p else p


def _read(p):
    return open(_path(p), encoding="utf-8").read().strip()


def _cfg():
    with open(CONFIG_F, encoding="utf-8") as f:
        c = json.load(f)
    for k in ("github_org", "github_token_file", "telegram_bot_token_file", "telegram_chat_id_file", "owner_id"):
        if k not in c:
            raise SystemExit("pr_gomb: missing config key: %s (%s)" % (k, CONFIG_F))
    c["owner_id"] = int(c["owner_id"])
    return c


CFG = None


def cfg():
    global CFG
    if CFG is None:
        CFG = _cfg()
    return CFG


def _gh(method, url, data=None):
    req = urllib.request.Request(url, data=json.dumps(data).encode() if data is not None else None, method=method,
                                 headers={"Authorization": "token " + _read(cfg()["github_token_file"]),
                                          "Accept": "application/vnd.github+json"})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, json.load(r)
    except urllib.error.HTTPError as e:
        try:
            body = json.load(e)
        except Exception:
            body = {"message": e.read()[:200].decode(errors="replace")}
        return e.code, body


def _tg(method, params):
    marker = cfg().get("disabled_marker")
    if marker and os.path.exists(_path(marker)):
        return {"ok": False, "disabled": True}
    token = _read(cfg()["telegram_bot_token_file"])
    data = urllib.parse.urlencode({k: (json.dumps(v) if isinstance(v, (dict, list)) else v)
                                   for k, v in params.items()}).encode()
    with urllib.request.urlopen("https://api.telegram.org/bot%s/%s" % (token, method), data=data, timeout=20) as r:
        return json.load(r)


def _append(path, rec):
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")


def _rows(path):
    if not os.path.exists(path):
        return []
    return [json.loads(l) for l in open(path, encoding="utf-8") if l.strip()]


def _pr(repo, n):
    org = cfg()["github_org"]
    st, p = _gh("GET", "https://api.github.com/repos/%s/%s/pulls/%d" % (org, repo, n))
    if st != 200:
        return None, "GitHub %s: %s" % (st, p.get("message"))
    st2, rv = _gh("GET", "https://api.github.com/repos/%s/%s/pulls/%d/reviews?per_page=100" % (org, repo, n))
    me = cfg().get("self_login") or org
    oth = [x for x in (rv if st2 == 200 else []) if x["user"]["login"] != me]
    return {"repo": repo, "pr": n, "title": p["title"], "head": p["head"]["sha"], "base": p["base"]["ref"],
            "state": p["state"], "mergeable_state": p.get("mergeable_state"),
            "review": (oth[-1]["state"] if oth else "no review from others")}, None


def kerd(repo, n, proba=False):
    pr, err = _pr(repo, n)
    if err:
        print("pr_gomb: REJECT — %s" % err)
        return 2
    rid = hashlib.sha256(("%s#%d@%s@%d" % (repo, n, pr["head"], int(time.time()))).encode()).hexdigest()[:8]
    text = ("MERGE DECISION %s\n%s #%d — %s\nbranch: %s\nhead: %s\nstate: %s · review: %s\n\n"
            "The button is the MERGE itself (merge commit), bound to the head ABOVE. If the head changes meanwhile, or a platform "
            "condition is missing (e.g. the other party's approval), it does NOT run, but says why."
            % (rid, repo, n, pr["title"][:80], pr["base"], pr["head"][:12], pr["mergeable_state"], pr["review"]))
    kb = {"inline_keyboard": [[{"text": "MERGE ✅", "callback_data": "M:" + rid},
                               {"text": "NO ❌", "callback_data": "N:" + rid}]]}
    if proba:
        print("[TRIAL — does not send, does not write the ledger]\n" + text + "\n" + json.dumps(kb, ensure_ascii=False))
        return 0
    out = _tg("sendMessage", {"chat_id": _read(cfg()["telegram_chat_id_file"]), "text": text, "reply_markup": kb})
    if not out.get("ok"):
        print("pr_gomb: the request did NOT go out (%s) — it was not written to the ledger either, so there is no pending request without a button"
              % ("Telegram DISABLED" if out.get("disabled") else out))
        return 1
    _append(KERELMEK, {"id": rid, "ts": int(time.time()), **pr, "message_id": out["result"]["message_id"]})
    print("pr_gomb: request sent, id=%s (%s #%d @ %s)" % (rid, repo, n, pr["head"][:12]))
    return 0


def _decided(rid):
    return any(d.get("id") == rid for d in _rows(DONTESEK))


def feldolgoz():
    owner = cfg()["owner_id"]
    org = cfg()["github_org"]
    kerelmek = {k["id"]: k for k in _rows(KERELMEK)}
    off = int(_read(OFFSET_F) or "0") if os.path.exists(OFFSET_F) else 0
    valaszok = _rows(VALASZOK)
    for i, v in enumerate(valaszok):
        if i < off:
            continue
        data = str(v.get("data") or "")
        act, _, rid = data.partition(":")
        rec = {"ts": int(time.time()), "id": rid, "valasz": data, "from_id": v.get("from_id")}
        if v.get("from_id") != owner:
            rec.update(eredmeny="IGNORED: the click was not the operator's")
            _append(DONTESEK, rec)
            continue
        k = kerelmek.get(rid)
        if not k:
            rec.update(eredmeny="UNKNOWN request id")
            _append(DONTESEK, rec)
            continue
        if _decided(rid):
            _tg("sendMessage", {"chat_id": owner, "text": "This request (%s) is already decided." % rid})
            continue
        if act == "N":
            rec.update(eredmeny="NO — a stated rejection (a third state: not silence)")
            _append(DONTESEK, rec)
            _tg("sendMessage", {"chat_id": owner, "text": "Recorded: NO — %s #%d does not go in." % (k["repo"], k["pr"])})
            continue
        if act != "M":
            rec.update(eredmeny="ISMERETLEN gomb-adat")
            _append(DONTESEK, rec)
            continue
        pr, err = _pr(k["repo"], k["pr"])
        if err:
            rec.update(eredmeny="DID NOT RUN: " + err)
            _append(DONTESEK, rec)
            _tg("sendMessage", {"chat_id": owner, "text": "Did NOT run: %s" % err})
            continue
        if pr["head"] != k["head"]:
            rec.update(eredmeny="DID NOT RUN: the head changed %s -> %s (the decision is bound to the head AT REQUEST TIME; make a new request)"
                       % (k["head"][:12], pr["head"][:12]))
            _append(DONTESEK, rec)
            _tg("sendMessage", {"chat_id": owner, "text": rec["eredmeny"]})
            continue
        st, out = _gh("PUT", "https://api.github.com/repos/%s/%s/pulls/%d/merge" % (org, k["repo"], k["pr"]),
                      {"merge_method": "merge", "sha": k["head"],
                       "commit_title": "Merge PR #%d (%s) — operator Telegram decision %s" % (k["pr"], k["repo"], rid)})
        if st == 200 and out.get("merged"):
            rec.update(eredmeny="MERGE OK", merge_sha=out.get("sha"))
            _append(DONTESEK, rec)
            _tg("sendMessage", {"chat_id": owner, "text": "MERGE OK: %s #%d -> merge-commit %s"
                                % (k["repo"], k["pr"], (out.get("sha") or "")[:12])})
        else:
            why = out.get("message") or str(out)
            rec.update(eredmeny="DID NOT RUN (GitHub %s): %s" % (st, why))
            _append(DONTESEK, rec)
            _tg("sendMessage", {"chat_id": owner, "text": "The merge did NOT run (%s #%d): %s — the button does not bypass the "
                                                          "platform's conditions." % (k["repo"], k["pr"], why)})
    open(OFFSET_F, "w").write(str(len(valaszok)))
    return 0


def allapot():
    d = {x["id"] for x in _rows(DONTESEK)}
    for k in _rows(KERELMEK):
        print("%-8s %-14s #%-3d %-12s %s" % (k["id"], k["repo"], k["pr"], k["head"][:12],
                                             "DECIDED" if k["id"] in d else "PENDING"))
    return 0


if __name__ == "__main__":
    a = sys.argv[1:]
    if not a:
        print(__doc__)
        sys.exit(2)
    if a[0] == "kerd" and len(a) >= 3:
        sys.exit(kerd(a[1], int(a[2]), proba="--proba" in a))
    if a[0] == "feldolgoz":
        sys.exit(feldolgoz())
    if a[0] == "allapot":
        sys.exit(allapot())
    print(__doc__)
    sys.exit(2)
