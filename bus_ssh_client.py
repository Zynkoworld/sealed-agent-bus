#!/usr/bin/env python3
"""bus_ssh_client — a TÁVOLI gép oldala: egy csere-kör a busz-géppel SSH-n (v1.2).

    python3 bus_ssh_client.py --target bus@host --local-identity me [--send-to X --body "…" --kind msg]

Egy kör: `ssh <target>` (a szerver oldalon a force-command csak a bus_ssh_exchange-et futtatja), stdin-en a kimenő
üzenetek + az előző körben tárolt legnagyobb válasz-id mint `ack`; a válaszok a HELYI buszra kerülnek
(recipient = local identity, sender = NÉVTEREZETT: `ssh:<host>~<a távoli fél által mondott feladó>`). A névtér a
határ: a szerver oldalon az identitás a force-command argumentumából jön és a payload
`from`/`sender` mezője nem számít — a kliens oldalon ugyanez a határ MEGFORDULT, a távoli válasz `sender`-e nyersen
lett a helyi feladó, tehát a távoli gép bármely HELYI agent (akár az operátor) nevében írhatott a helyi buszra.
Mostantól egy távoli gép SOHA nem írhat helyi néven: a helyi sor feladója mindig a távoli cél + a mondott név
összetétele, és a mondott névből a `/` és minden nem [A-Za-z0-9_.-] karakter kiesik (a registry `basename`-alapú
kulcs-feloldása így sem eshet vissza egy helyi névre). A tárolt legnagyobb id egy állapotfájlban él →
ugyanaz a válasz kétszer nem kerül a helyi buszra, és a szerver kurzora csak a sikeres helyi tárolás UTÁN lép.

Az `ssh` parancs cserélhető (`ssh_cmd`), így a teszt egy helyi hamis ssh-val futtatja a végpontot — valódi
hostra a tesztek nem csatlakoznak. Csatolmány: `attach_descs` leírói a helyi tárból darabolva mennek. stdlib-only."""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

DEFAULT_SSH = ["ssh", "-o", "BatchMode=yes", "-o", "ServerAliveInterval=15", "-T"]


def _state_path(state_dir: str, target: str, local_identity: str) -> str:
    import agent_bus as ab
    return os.path.join(state_dir, "ssh_%s__%s.json" % (ab._safe_name(target), ab._safe_name(local_identity)))


_CLAIMED_MAX = 48


def remote_sender_name(target: str, claimed) -> str:
    """A HELYI buszra kerülő feladó-név egy távoli válaszhoz: `ssh:<host>~<mondott>`.
    (2026-09-17): a mondott név nyersen a helyi feladó lett → a távoli gép helyi agent nevében írt.
    A névtér a kliens kimondott határa: a távoli fél a `~` UTÁNI részt választja meg, a HELYI névteret nem érheti el.
    A mondott részből minden nem [A-Za-z0-9_.-] karakter (így a `/`, szóköz, vezérlő) `_` lesz, és 48 karakterre
    vág — a registry kulcs-feloldása `basename`-alapú, tehát egy `../hub` sem eshet vissza a helyi `hub`-ra.
    Üres/nem-string mondott név → `?` (kimondva, nem csendben)."""
    host = str(target or "").rsplit("@", 1)[-1] or "?"
    host = "".join(ch if (ch.isalnum() or ch in "_.-") else "_" for ch in host)[:_CLAIMED_MAX] or "?"
    raw = claimed if isinstance(claimed, str) else ""
    safe = "".join(ch if (ch.isalnum() or ch in "_.-") else "_" for ch in raw)[:_CLAIMED_MAX]
    if not safe or safe.strip(".") == "":
        safe = "?"
    return "ssh:%s~%s" % (host, safe)


def receipts_path(state_dir: str, target: str, local_identity: str) -> str:
    """A távoli fél nyugta-listája (JSONL, körönként): ezt veti össze a `bus_notary reconcile` a busz-gép naplójával."""
    return _state_path(state_dir, target, local_identity)[:-len(".json")] + ".receipts.jsonl"


def _load_state(path: str) -> dict:
    try:
        with open(path, encoding="utf-8") as f:
            st = json.load(f)
        return st if isinstance(st, dict) else {}
    except (OSError, ValueError):
        return {}


def _save_state(path: str, st: dict) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(st, f)
    os.replace(tmp, path)


def sign_outgoing(local_identity: str, messages, *, sign_key=None, keys_dir=None):
    """v1.5.2 (2026-09-21): a kimenő üzeneteket a KLIENS a saját kulcsával írja alá (`ts`/`sig`/`pubkey` a message-en),
    hogy a busz-gépen tárolt sor a címzett termék-módú olvasásában `signed` legyen (a busz-gép elvből nem írja alá a
    távoli fél sorát; a registry-ben pinelt név alatti csupasz sort pedig a termék-mód eldobja — 09-19..21 két gép
    közt minden sor így tűnt el némán). Kulcs: `sign_key`, különben `<keys_dir>/<local_identity>.ed25519.key`
    (AGENT_BUS_KEYS_DIR); ha nincs kulcs, a message változatlan marad (a szerver okkal utasítja el, ha pinelt).
    Az aláírt tartalom `sender` mezője a helyi identitás — a szerver a force-command identitását teszi feladónak,
    tehát ha a kettő eltér, az aláírás nem verifikál (ez a szándék: nem lehet más nevében aláírni)."""
    import agent_bus as ab
    out = []
    key = sign_key
    if key is None:
        cand = os.path.join(keys_dir or ab.KEYS_DIR, "%s.ed25519.key" % os.path.basename(local_identity))
        key = cand if os.path.isfile(cand) else None
    for m in list(messages or []):
        if not isinstance(m, dict) or key is None or m.get("sig") is not None:
            out.append(m)
            continue
        # A kimenő oldal SEM normalizál a maga feje szerint: ugyanazt a `canonical_text_field`-et hívja,
        # amit a bájtkép-építő és a bejövő út. Korábban itt is `or "msg"` állt — a négy hely csak
        # VÉLETLENÜL egyezett, és amikor kettőt a specre igazítottam, a másik kettő azonnal elvált.
        pre = ab.sign_for_send(key, local_identity, str(m.get("to", "")),
                               ab.canonical_text_field(m.get("body")),
                               topic=ab.canonical_text_field(m.get("topic")),
                               kind=ab.canonical_text_field(m.get("kind")),
                               in_reply_to=m.get("in_reply_to"))
        out.append(dict(m, **pre))
    return out


def exchange(target: str, local_identity: str, messages=None, *, ssh_cmd=None, state_dir=None, db=None,
             attach_descs=None, attach_root=None, timeout: float = 120.0, sign_key=None) -> dict:
    """Egy csere-kör. -> a szerver válasz-objektuma + `stored_locally` (a helyi buszra írt válaszok száma)."""
    import agent_bus as ab
    import bus_attach
    state_dir = state_dir or os.path.join(os.path.dirname(ab.DB), "remote_state")
    sp = _state_path(state_dir, target, local_identity)
    st = _load_state(sp)
    payload = {"ack": int(st.get("stored_max", 0)), "messages": sign_outgoing(local_identity, messages, sign_key=sign_key)}
    if attach_descs:
        store = bus_attach.Store(attach_root)
        payload["attachments"] = [{"descriptor": d, "chunks": list(store.chunks(d))} for d in attach_descs]
    # nyugta: a kérés-sor (küldött dictek + ack) a KÜLDÉS ELŐTT kerül a fájlba, egy
    # kör-azonosítóval; a kör VÉGE új sorral írja a kimenetelt (append-only): not-sent (bizonyíthatóan nem ment ki),
    # unknown (kimehetett, a válasz nem jött / hibás), delivered (a szerver válaszolt; a kapott válaszokkal és a horgonnyal).
    # A reconcile csak a delivered körből vádol; az unknown külön "unresolved" lista, a not-sent nem vád.
    rp = receipts_path(state_dir, target, local_identity)
    round_id = "%d-%s" % (time.time_ns(), os.urandom(4).hex())
    os.makedirs(state_dir, exist_ok=True)

    def _receipt(row):
        with open(rp, "a", encoding="utf-8") as f:
            f.write(json.dumps(dict(row, round=round_id), ensure_ascii=False, sort_keys=True) + "\n")
    _receipt({"phase": "request", "sent": payload["messages"], "ack": payload["ack"], "received": []})
    cmd = list(ssh_cmd or DEFAULT_SSH) + [target]
    try:
        proc = subprocess.run(cmd, input=json.dumps(payload).encode(), capture_output=True, timeout=timeout)
    except OSError as e:                                        # az ssh el sem indult
        _receipt({"phase": "outcome", "outcome": "not-sent", "reason": str(e)[:200]})
        return {"error": "ssh could not start: %s" % e}
    except subprocess.TimeoutExpired:
        _receipt({"phase": "outcome", "outcome": "unknown", "reason": "timeout"})
        raise
    try:
        out_txt = proc.stdout.decode("utf-8", "replace")
        res = json.loads(out_txt) if out_txt.strip() else None   # C1: üres kimenet NEM érvényes válasz
    except ValueError:
        res = None
    if not isinstance(res, dict) or "error" in res:
        # ssh 255 = a kapcsolat nem épült fel (a végpont maga 0/2-vel lép ki) -> not-sent; nem-JSON egyéb -> unknown.
        # érvényes JSON-objektum válasz (akár {"error":...}) = a kérés BIZONYÍTOTTAN odaért
        # -> reached (a reconcile úgy vádol, mint delivered-nél). A kör-kimenetel a "bizonyítottan odaért-e" kérdésre felel.
        # HÁROM fok. bizonyított: delivered/reached · feltételezett: timeout, rc 255 + nem-JSON,
        # processed:false (a vádlott aláíratlan szava) · kizárt: OSError (az ssh el sem indult) -> csak az a not-sent.
        claimed = isinstance(res, dict) and res.get("processed") is False
        if claimed:
            outcome = "unknown"
        elif isinstance(res, dict):
            outcome = "reached"
        else:                            # a címke marad (not-sent / unknown), de az rc 255 NEM kizárt: a reconcile az
            outcome = "not-sent" if proc.returncode == 255 else "unknown"   # rc-t hordozó not-sent-et FELTÉTELEZETTNEK veszi
        row = {"phase": "outcome", "outcome": outcome, "rc": proc.returncode,
               "error": (res or {}).get("error") if isinstance(res, dict) else "non-JSON reply"}
        if claimed:
            row["peer_claimed_unprocessed"] = True
        if isinstance(res, dict):        # az error MELLETT jött replies/horgony is a nyugtába kerül
            row["received"] = res.get("replies") or []
            if res.get("notary"):
                row["notary"] = res.get("notary")
        _receipt(row)
        if res is None:
            return {"error": "non-JSON reply from endpoint", "rc": proc.returncode}
        if not isinstance(res, dict):
            return {"error": "reply must be a JSON object", "rc": proc.returncode}
    else:
        _receipt({"phase": "outcome", "outcome": "delivered", "received": res.get("replies") or [],
                  "accepted": res.get("accepted"), "notary": res.get("notary")})
    stored, top = 0, int(st.get("stored_max", 0))
    # korábban itt PROCESS-GLOBÁLISAN állt AGENT_BUS_AUTO_SIGN=0, és sosem állt vissza — egy hosszabb életű
    # hívó (pl. a CI őrszeme) minden későbbi küldése aláíratlan maradt. Az opt-out most HÍVÁS-SZINTŰ: `sign_key=False`.
    for r in res.get("replies") or []:
        rid = r.get("id")
        if not isinstance(rid, int) or rid <= top:
            continue                                            # már tárolt (előző kör, ack előtti megszakadás) → dedupe
        try:
            # a feladó NÉVTEREZETT — a távoli gép nem választhat helyi nevet (lásd remote_sender_name)
            ab.send(remote_sender_name(target, r.get("sender")), local_identity, str(r.get("body", "")),
                    topic=str(r.get("topic") or ""), kind=str(r.get("kind") or "msg"), db=db, sign_key=False)
            stored += 1
        except ValueError:
            pass                                                # a helyi busz szabálya (pl. rossz sds-keret) → nem tároljuk
        top = max(top, rid)
    if top != int(st.get("stored_max", 0)):
        st["stored_max"] = top
        _save_state(sp, st)
    res["stored_locally"] = stored
    return res


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="one SSH exchange round with a remote AgentBus")
    p.add_argument("--target", required=True)
    p.add_argument("--local-identity", required=True)
    p.add_argument("--send-to")
    p.add_argument("--body")
    p.add_argument("--kind", default="msg")
    p.add_argument("--topic", default="")
    a = p.parse_args(argv)
    msgs = [{"to": a.send_to, "body": a.body, "kind": a.kind, "topic": a.topic}] if a.send_to and a.body is not None else []
    res = exchange(a.target, a.local_identity, msgs)
    print(json.dumps({k: v for k, v in res.items() if k != "replies"}, ensure_ascii=False))
    return 2 if "error" in res else 0


if __name__ == "__main__":
    sys.exit(main())
