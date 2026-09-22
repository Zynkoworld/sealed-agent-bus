#!/usr/bin/env python3
"""pr_gomb — merge-jóváhagyás Telegram-gombbal: az OPERÁTOR EGY KULCSA a saját oldalán.

MIÉRT: a két-kulcsos szabálynak nulla kulcsa lett — mindkét agent emberhez utalta a döntést,
de a szabály mindkét kulcsot agentre osztotta. Ez a csomag az EMBERI kulcs: egy PR-kártya Telegramon két gombbal
([MERGE ✅] [NEM ❌]), és a kattintás maga a merge — vagy annak kimondott elmaradása.

MIT TESZ ÉS MIT NEM (kimondva):
  * a gomb = a MERGE MAGA, ami CSAK akkor fut le, ha a platform többi feltétele áll (kötelező jóváhagyás megvan, a fej
    nem változott); különben KIMONDJA, miért nem — soha nem kerüli meg a branch-védelmet;
  * a merge módja MINDIG merge-commit (soha squash/rebase: a base-pin horgonyok a merge-commit SHA-jára mutatnak);
  * a döntés a KÉRÉSKORI FEJ-SHA-hoz kötött: ha a PR feje azóta változott, a gomb nem hajtja végre, új kérést kér;
  * CSAK az operátor (OWNER_ID) kattintása számít; minden más feladó rögzítve, de figyelmen kívül hagyva;
  * egy kérés EGYSZER dönthető el (idempotens); a második kattintás „már eldöntve" választ kap;
  * minden könyv append-only (kerelmek / valaszok / dontesek.jsonl) — semmi nem törlődik;
  * a GitHub-token és a bot-token soha nem kerül kimenetre/naplóba.

Beállítás: `config.json` a fájl mellett (lásd config.example.json) — vagy `PR_GOMB_CONFIG` env a fájl útjával.
  {
    "github_org":     "Zynkoworld",                      # a repók tulajdonosa (org vagy user)
    "github_token_file": "~/.config/agentbus/github_token",          # repo-scope token, a fájl 0600
    "telegram_bot_token_file": "~/.config/agentbus/telegram_bot_token",
    "telegram_chat_id_file":   "~/.config/agentbus/telegram_chat_operator",   # az operátor privát chatje a bottal
    "owner_id": 123456789,                               # az operátor Telegram user-id-ja (CSAK az ő kattintása számít)
    "self_login": "Zynkoworld",                          # a PR-ek szerzője: ennek a review-ja nem „másé"
    "disabled_marker": "~/.config/agentbus/telegram_DISABLED" # ha létezik, a bot nem küld (kikapcsolás fájllal, nem kóddal)
  }

Használat:
  pr_gomb.py kerd <repo> <pr>          # kérés: PR-kártya + [MERGE ✅] [NEM ❌] gomb az operátornak
  pr_gomb.py kerd <repo> <pr> --proba  # csak megmutatja, mit küldene (nem küld, nem ír könyvet)
  pr_gomb.py feldolgoz                 # a beérkezett gomb-válaszok végrehajtása (cronból, percenként)
  pr_gomb.py allapot                   # függő kérések

A gomb-válaszokat a `telegram_gomb_poll.py` írja a `valaszok.jsonl`-be (callback_query → sor); ez a fájl NEM dönt semmiről.
Cron (mindig fájlon át, soha csövön): lásd crontab.example.
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
    """A konfigban `~` is állhat — a defaultok szándékosan a felhasználó saját könyvtárára mutatnak, nem egy
    konkrét gép elrendezésére, ezért minden config-beli utat itt bontunk ki egy helyen."""
    return os.path.expanduser(p) if p else p


def _read(p):
    return open(_path(p), encoding="utf-8").read().strip()


def _cfg():
    with open(CONFIG_F, encoding="utf-8") as f:
        c = json.load(f)
    for k in ("github_org", "github_token_file", "telegram_bot_token_file", "telegram_chat_id_file", "owner_id"):
        if k not in c:
            raise SystemExit("pr_gomb: hiányzó config-kulcs: %s (%s)" % (k, CONFIG_F))
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
            "review": (oth[-1]["state"] if oth else "nincs review mástól")}, None


def kerd(repo, n, proba=False):
    pr, err = _pr(repo, n)
    if err:
        print("pr_gomb: REJECT — %s" % err)
        return 2
    rid = hashlib.sha256(("%s#%d@%s@%d" % (repo, n, pr["head"], int(time.time()))).encode()).hexdigest()[:8]
    text = ("MERGE-DÖNTÉS %s\n%s #%d — %s\nág: %s\nfej: %s\nállapot: %s · review: %s\n\n"
            "A gomb a MERGE maga (merge-commit), a FENTI fejhez kötve. Ha a fej közben változik, vagy a platform "
            "feltétele hiányzik (pl. a másik fél jóváhagyása), NEM fut le, hanem megmondja, miért."
            % (rid, repo, n, pr["title"][:80], pr["base"], pr["head"][:12], pr["mergeable_state"], pr["review"]))
    kb = {"inline_keyboard": [[{"text": "MERGE ✅", "callback_data": "M:" + rid},
                               {"text": "NEM ❌", "callback_data": "N:" + rid}]]}
    if proba:
        print("[PRÓBA — nem küld, nem ír könyvet]\n" + text + "\n" + json.dumps(kb, ensure_ascii=False))
        return 0
    out = _tg("sendMessage", {"chat_id": _read(cfg()["telegram_chat_id_file"]), "text": text, "reply_markup": kb})
    if not out.get("ok"):
        print("pr_gomb: a kérés NEM ment ki (%s) — könyvbe sem került, hogy ne legyen függő kérés gomb nélkül"
              % ("Telegram KIKAPCSOLVA" if out.get("disabled") else out))
        return 1
    _append(KERELMEK, {"id": rid, "ts": int(time.time()), **pr, "message_id": out["result"]["message_id"]})
    print("pr_gomb: kérés kiment, id=%s (%s #%d @ %s)" % (rid, repo, n, pr["head"][:12]))
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
            rec.update(eredmeny="FIGYELMEN KIVUL: nem az operátor kattintott")
            _append(DONTESEK, rec)
            continue
        k = kerelmek.get(rid)
        if not k:
            rec.update(eredmeny="ISMERETLEN kérés-id")
            _append(DONTESEK, rec)
            continue
        if _decided(rid):
            _tg("sendMessage", {"chat_id": owner, "text": "Ez a kérés (%s) már el van döntve." % rid})
            continue
        if act == "N":
            rec.update(eredmeny="NEM — kimondott elutasítás (harmadik állapot: nem csend)")
            _append(DONTESEK, rec)
            _tg("sendMessage", {"chat_id": owner, "text": "Rögzítve: NEM — %s #%d nem megy be." % (k["repo"], k["pr"])})
            continue
        if act != "M":
            rec.update(eredmeny="ISMERETLEN gomb-adat")
            _append(DONTESEK, rec)
            continue
        pr, err = _pr(k["repo"], k["pr"])
        if err:
            rec.update(eredmeny="NEM FUTOTT: " + err)
            _append(DONTESEK, rec)
            _tg("sendMessage", {"chat_id": owner, "text": "NEM futott le: %s" % err})
            continue
        if pr["head"] != k["head"]:
            rec.update(eredmeny="NEM FUTOTT: a fej változott %s -> %s (a döntés a KÉRÉSKORI fejhez kötött; kérj újat)"
                       % (k["head"][:12], pr["head"][:12]))
            _append(DONTESEK, rec)
            _tg("sendMessage", {"chat_id": owner, "text": rec["eredmeny"]})
            continue
        st, out = _gh("PUT", "https://api.github.com/repos/%s/%s/pulls/%d/merge" % (org, k["repo"], k["pr"]),
                      {"merge_method": "merge", "sha": k["head"],
                       "commit_title": "Merge PR #%d (%s) — operátor Telegram-döntés %s" % (k["pr"], k["repo"], rid)})
        if st == 200 and out.get("merged"):
            rec.update(eredmeny="MERGE OK", merge_sha=out.get("sha"))
            _append(DONTESEK, rec)
            _tg("sendMessage", {"chat_id": owner, "text": "MERGE OK: %s #%d -> merge-commit %s"
                                % (k["repo"], k["pr"], (out.get("sha") or "")[:12])})
        else:
            why = out.get("message") or str(out)
            rec.update(eredmeny="NEM FUTOTT (GitHub %s): %s" % (st, why))
            _append(DONTESEK, rec)
            _tg("sendMessage", {"chat_id": owner, "text": "NEM futott le a merge (%s #%d): %s — a gomb nem kerüli meg a "
                                                          "platform feltételeit." % (k["repo"], k["pr"], why)})
    open(OFFSET_F, "w").write(str(len(valaszok)))
    return 0


def allapot():
    d = {x["id"] for x in _rows(DONTESEK)}
    for k in _rows(KERELMEK):
        print("%-8s %-14s #%-3d %-12s %s" % (k["id"], k["repo"], k["pr"], k["head"][:12],
                                             "ELDÖNTVE" if k["id"] in d else "FÜGGŐ"))
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
