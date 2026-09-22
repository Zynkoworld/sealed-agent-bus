#!/usr/bin/env python3
"""bus_ssh_exchange — SSH-SZÁLLÍTÁS gépek között: a FOGADÓ gép force-command végpontja (v1.2).

Modell (a júliusi SSH-bridge általánosítva): a távoli agent KIFELÉ SSH-zik a busz gépére (kliens-kezdeményezés,
NAT-on át, a távoli gépen NINCS portnyitás). Az SSH adja a titkosítást + a kliens-kulcsos hitelesítést; a busz-gépen
az authorized_keys sora `command="… bus_ssh_exchange.py <identity>",restrict,…` → ez a szkript fut, SEMMI MÁS
(nincs shell, pty, port-forward). Lásd bus_ssh_enroll.py.

Egy SSH-hívás = egy atomi csere-kör (stdin JSON → stdout JSON):

    be:  {"ack": <utolsó tárolt válasz-id | 0>,
          "messages": [{"to", "body", "topic"?, "kind"?, "thread_id"?, "in_reply_to"?}, …],
          "attachments": [{"descriptor": {…}, "chunks": [{"sha256","seq","last","data"}, …]}, …]}
    ki:  {"identity", "protocol", "accepted": [bus-id…], "rejected": [{"index", "reason"}…],
          "attachments": [{"sha256", "status": "stored|partial|rejected", "reason"?}…],
          "replies": [{"id","ts","sender","topic","kind","thread_id","in_reply_to","body","sds"?}…]}

Biztonsági határ:
- **Az identitás a force-command ARGUMENTUMÁBÓL jön** (a kulcshoz kötve), SOHA nem a payloadból: a
  `from`/`sender` mezők figyelmen kívül maradnak (anti-spoof).
- **Méret-plafonok:** a teljes stdin ≤ MAX_BYTES; üzenet/kör ≤ MAX_MESSAGES; a body a busz saját 64 KB-os cap-je.
- **sds-envelope átmegy:** a busz `send` a keretet ellenőrzi; a boríték ALÁÍRÁSÁT a fogadó oldalon a v1.1
  `recv --verify-sds` útja nézi — a válaszokban a `sds` mező ezt a címkét adja.
- **A busz-sort ez a végpont NEM írja alá** a busz-gép kulcsával (AUTO-SIGN ki): a távoli feladó hitelességét az
  SSH-kulcs adja, a tartalomét az sds-envelope saját aláírása.
- **v1.5.2 — kliens-aláírt sor:** a message hozhat `ts`/`sig`/`pubkey`-t (a feladó SAJÁT Ed25519-kulcsával, a busz
  `sign_for_send` alakjában); a végpont a registry-kulcs ellen ellenőrzi és pontosan azt tárolja → a címzett
  termék-módban `signed`-nek látja. Csupasz sor egy registry-ben PINELT név alatt termék-módban: `rejected` okkal
  (`unsigned-pinned`) — nem tárolódik, hogy aztán olvasáskor némán eldobódjon.
- **Legalább-egyszer kézbesítés:** a válaszok PEEK-kel mennek ki; a kurzor csak a kliens KÖVETKEZŐ körbeli `ack`-jára
  lép (ha az SSH megszakad, semmi nem vész el). stdlib-only."""
from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

MAX_BYTES = int(os.environ.get("AGENT_BUS_SSH_MAX_BYTES", str(4 * 1024 * 1024)))
MAX_MESSAGES = 200
MAX_REPLIES = 200
# DOWNLOAD (fetch) plafonok: egy csere-kör ennyi csatolmány-bájtot ad vissza; a nagyobbat kulon korben, dedikaltan
# kell kerni. A DL a content-addressed tarbol megy (a sha256 a kepesseg: aki egy neki cimzett uzenetben megkapta a
# leirot, az le tudja huzni). Az env csak SZUKITHET (mint a bus_enforce-nal).
MAX_FETCH_ITEMS = 32
MAX_FETCH_BYTES = min(4 * 1024 * 1024, int(os.environ.get("AGENT_BUS_SSH_FETCH_MAX_BYTES", str(4 * 1024 * 1024))))
_REPLY_KEYS = ("id", "ts", "sender", "topic", "kind", "thread_id", "in_reply_to", "body", "sds")


_FROM_ENV = object()


def exchange(identity: str, raw: bytes | str, *, db=None, attach_root=None, notary=_FROM_ENV) -> dict:
    try:
        return _exchange(identity, raw, db=db, attach_root=attach_root, notary=notary)
    except _NotaryWriteFailed as e:                            # fail-closed: a hátralévő tételek nem mennek át, nincs traceback
        return dict(e.args[0], error="notary write failed (fail-closed)")


class _NotaryWriteFailed(Exception):
    pass


def _exchange(identity, raw, *, db, attach_root, notary):
    import agent_bus as ab
    import bus_attach
    import bus_notary

    if notary is _FROM_ENV:                                    # v1.5: közjegyzői napló — termék-módban kötelező (fail-closed)
        try:
            notary = bus_notary.Notary.from_env(db=db)
        except (bus_notary.NotaryError, OSError, ValueError):
            return {"identity": identity, "error": "notary unavailable (fail-closed)", "processed": False}

    def note(**kw):                                            # csak hash + metaadat; a nyílt test sosem kerül a naplóba
        # dob → _NotaryWriteFailed; a hívóhelyek a mellékhatás (send / tárba írás / ack / kiadás) ELŐTT hívják
        if notary is not None:
            try:
                e = notary.record(sender_identity=identity, sender_auth="ssh-key", **kw)
            except Exception:
                raise _NotaryWriteFailed(out)
            if isinstance(e, dict) and "seq" in e:             # napló-horgony a válaszban: a kör utolsó bejegyzése
                out["notary"] = {"seq": e["seq"], "head_hash": e["entry_hash"]}

    # (2026-09-17): itt PROCESS-GLOBÁLISAN állt AGENT_BUS_AUTO_SIGN=0, és sosem állt vissza. A force-command
    # rövid életű folyamatában ez láthatatlan volt; egy hosszabb életű hívóban (a CI sweep_log_probe őrszeme ugyanebben a
    # folyamatban hívja) minden KÉSŐBBI küldés is aláíratlan maradt, amit a termék-mód eldobott. Az elv marad — a
    # busz-gép kulcsa NEM írja alá a távoli üzenetét —, de HÍVÁS-SZINTEN: az `ab.send(..., sign_key=False)` az auto-signt
    # is kikapcsolja arra az egy sorra, más folyamat-állapotot nem érint.
    if isinstance(raw, bytes):
        if len(raw) > MAX_BYTES:
            return {"identity": identity, "error": "oversize", "processed": False}
        raw = raw.decode("utf-8", "replace")
    elif len(raw.encode("utf-8", "surrogatepass")) > MAX_BYTES:
        return {"identity": identity, "error": "oversize", "processed": False}
    out = {"identity": identity, "protocol": ab.PROTOCOL_VERSION, "accepted": [], "rejected": [],
           "attachments": [], "fetched": [], "replies": []}
    payload = {}
    if raw.strip():
        try:
            payload = json.loads(raw)
        except ValueError:
            return dict(out, error="payload is not JSON")
        if not isinstance(payload, dict):
            return dict(out, error="payload must be a JSON object")
    msgs = payload.get("messages") or []
    if not isinstance(msgs, list) or len(msgs) > MAX_MESSAGES:
        return dict(out, error="messages must be a list of at most %d" % MAX_MESSAGES)

    ack_to = payload.get("ack")
    if isinstance(ack_to, int) and not isinstance(ack_to, bool) and ack_to > 0:
        # KIMENŐ IRÁNY, NAPLÓZÁS-ELŐBB: az ack véglegesen elfogyasztja a postát (előre-only
        # kurzor), ezért a kurzor régi->új értéke a mozgatás ELŐTT kerül a naplóba; naplóhiba -> nincs kurzor-mozgás.
        base, tgt = ab.ack_preview(identity, ack_to, db=db)
        note(envelope={"ack": ack_to, "cursor_from": base, "cursor_to": tgt}, recipient=identity, kind="ack",
             decision="accepted", reason="cursor %d->%d (ack %d)" % (base, tgt, ack_to),
             cursor={"from": base, "to": tgt, "ack": ack_to})
        try:
            ab.ack(identity, ack_to, db=db)                    # az ack előre-only és a valós üzenetekre clamp-el (a busz szabálya)
        except Exception:                                      # noqa: BLE001 — a kurzor nem mozdult: korrigáló bejegyzés
            note(envelope={"ack": ack_to, "cursor_from": base, "cursor_to": tgt}, recipient=identity, kind="ack",
                 decision="rejected", reason="ack_failed")

    for i, m in enumerate(msgs):
        if not isinstance(m, dict) or not isinstance(m.get("to"), str) or not isinstance(m.get("body"), str):
            out["rejected"].append({"index": i, "reason": "message needs string 'to' and 'body'"})
            note(envelope=m, recipient=(m.get("to") if isinstance(m, dict) else ""), kind="msg", decision="rejected",
                 reason="malformed")
            continue
        claimed = bus_notary.claimed_ts_of(m)
        # A BEJÖVŐ ÚT NEM NORMALIZÁL A MAGA FEJE SZERINT. Korábban itt `m.get("kind","msg") or "msg"` állt,
        # ami az elhagyott, az ÜRES és a `null` kindot is `"msg"`-gé tette — miközben az aláírt bájtkép
        # mindhármat `""`-nek számolja. Egy spec szerint aláíró partner sora ezért `presigned: signature
        # does not verify (forged or tampered)`-rel bukott: nem csendes elutasítás, HAMISÍTÁS-VÁD.
        kind = ab.canonical_text_field(m.get("kind"))
        # NAPLÓZÁS-ELŐBB: a fogadás ténye a busz-beszúrás ELŐTT kerül a naplóba. Ha a naplóírás
        # dob, az ab.send meg sem hívódik (valódi fail-closed, újraküldésnél sincs naplózatlan másolat). Ha a send dob
        # a naplózás után, egy második, rejected bejegyzés korrigál: túl-naplózás megengedett, alul-naplózás nem.
        # v1.5.2 (2026-09-21): KLIENS-ALÁÍRT sor. A távoli fél a SAJÁT kulcsával írta alá (`sig`/`pubkey`/`ts` a
        # message-en), a busz-gép a registry ellen ellenőrzi és PONTOSAN azt tárolja — így a címzett termék-módú
        # olvasása `signed`-nek látja. Csupasz sor egy PINELT név alatt termék-módban: az olvasó úgyis eldobná
        # (`unsigned-pinned`), ezért ITT utasítjuk el, OKKAL, hogy a feladó lássa (09-19..21: 25+7064 sor tűnt el némán).
        presigned = None
        if m.get("sig") is not None or m.get("pubkey") is not None:
            presigned = {"ts": m.get("ts"), "sig": m.get("sig"), "pubkey": m.get("pubkey")}
        elif ab._is_product(db) and ab._a2_load_registry_pubkey(identity, ab.KEYS_DIR) is not None:
            reason = "unsigned-pinned: '%s' has a registry key; sign client-side (keys/%s.ed25519.key)" % (identity, identity)
            out["rejected"].append({"index": i, "reason": reason})
            note(envelope=m, recipient=m["to"], kind=kind, decision="rejected", reason="unsigned-pinned",
                 claimed_ts=claimed)
            continue
        note(envelope=m, recipient=m["to"], kind=kind, decision="accepted", claimed_ts=claimed)
        try:                                                   # ANTI-SPOOF: a feladó MINDIG a pinelt identitás
            rid = ab.send(identity, m["to"], m["body"], topic=ab.canonical_text_field(m.get("topic")),
                          kind=kind, thread_id=m.get("thread_id"),
                          in_reply_to=m.get("in_reply_to"), db=db, sign_key=False,   # False = NINCS auto-sign sem
                          presigned=presigned)
        except Exception as e:                                 # noqa: BLE001 — bármely send-hiba: nem kézbesült, és ez látszik
            out["rejected"].append({"index": i, "reason": str(e)[:200]})
            note(envelope=m, recipient=m["to"], kind=kind, decision="rejected", reason="send_failed",
                 claimed_ts=claimed)
            continue
        out["accepted"].append(rid)

    store = bus_attach.Store(attach_root)
    for a in payload.get("attachments") or []:
        desc = (a or {}).get("descriptor") if isinstance(a, dict) else None
        sha = desc.get("sha256") if isinstance(desc, dict) else None
        env = desc if isinstance(desc, dict) else {}
        try:                                                   # tisztán alaki ellenőrzés, a tárhoz még nem nyúl
            bus_attach.check_descriptor(desc)
            chunks = a.get("chunks") or []
            if not isinstance(chunks, list):
                raise TypeError("chunks must be a list")
        except (bus_attach.AttachmentError, AttributeError, TypeError) as e:
            out["attachments"].append({"sha256": sha, "status": "rejected", "reason": str(e)[:200]})
            note(envelope=env, recipient="", kind="attachment", decision="rejected", reason=str(e)[:200])
            continue
        # NAPLÓZÁS-ELŐBB a csatolmány-ágon is: a tárba írás (partial vagy kész) csak a bejegyzés után történik.
        note(envelope=env, recipient="", kind="attachment", decision="accepted", reason="received")
        try:
            done = None
            for ch in chunks:
                done = store.receive_chunk(desc, ch)
        except Exception as e:                                 # noqa: BLE001 — nem tárolódott: második, korrigáló bejegyzés
            out["attachments"].append({"sha256": sha, "status": "rejected", "reason": str(e)[:200]})
            note(envelope=env, recipient="", kind="attachment", decision="rejected", reason="store_failed")
            continue
        out["attachments"].append({"sha256": sha, "status": "stored" if done else "partial"})

    # DOWNLOAD (fetch): a kliens leirokat (descriptor) ker, a content-addressed tarbol visszaadjuk a darabokat.
    # Ez a hianyzo fogado-oldala + a "busz csomagot is szallit" letoltes-iranya. A get() bajtra ellenoriz
    # (size+sha256, fail-closed). Per-kor plafon: MAX_FETCH_ITEMS db es MAX_FETCH_BYTES ossz-bajt; a nagyot kulon korben.
    fetched_bytes = 0
    for desc in (payload.get("fetch") or [])[:MAX_FETCH_ITEMS]:
        sha = desc.get("sha256") if isinstance(desc, dict) else None
        env = desc if isinstance(desc, dict) else {}
        try:
            bus_attach.check_descriptor(desc)                  # tisztan alaki
        except (bus_attach.AttachmentError, AttributeError, TypeError) as e:
            out["fetched"].append({"sha256": sha, "status": "rejected", "reason": str(e)[:200]})
            note(envelope=env, recipient=identity, kind="fetch", decision="rejected", reason=str(e)[:200])
            continue
        size = desc.get("size") if isinstance(desc.get("size"), int) else 0
        if fetched_bytes + size > MAX_FETCH_BYTES:             # a nagyot dedikalt korben kell kerni (nem nema csonkolas)
            out["fetched"].append({"sha256": sha, "status": "deferred", "reason": "round-fetch-budget"})
            note(envelope=env, recipient=identity, kind="fetch", decision="rejected", reason="round-budget")
            continue
        note(envelope=env, recipient=identity, kind="fetch", decision="accepted", reason="requested")
        try:
            chunks = list(store.chunks(desc))                  # get() bajtra ellenoriz (size+sha256) -> nem-tarolt = AttachmentError
        except bus_attach.AttachmentError as e:                # nincs a tarban / eltero -> nem talalt (fail-closed)
            out["fetched"].append({"sha256": sha, "status": "not-found", "reason": str(e)[:200]})
            note(envelope=env, recipient=identity, kind="fetch", decision="rejected", reason="not-found")
            continue
        fetched_bytes += size
        out["fetched"].append({"sha256": sha, "descriptor": desc, "chunks": chunks, "status": "delivered"})

    rows = ab.recv(identity, mark=False, limit=MAX_REPLIES, db=db, verify_sds=True)
    _PEND_LIMIT = MAX_REPLIES * 50
    try:        # a KIADÁSRA VÁRÓ darabszám ÉS az első ki NEM adott id a bizonyítékba is
        pend_rows = ab.recv(identity, mark=False, limit=_PEND_LIMIT + 1, db=db, verify_sds=True)   # +1 = csonkolás-érzékelő
        pend_ok = True
    except Exception:
        pend_rows, pend_ok = rows, False          # a mérés HIÁNYÁT ki kell mondani, nem „tiszta kör"-nek látszani
    # Saját a +1-es érzékelőt eddig senki nem olvasta — a limitbe ütköző mérés CSONKA, és egy
    # csonka `pending` „tiszta kör"-nek látszott volna. A csonkolás ugyanaz a harmadik állapot, mint a mérés hiánya.
    pend_truncated = pend_ok and len(pend_rows) > _PEND_LIMIT
    pending = len(pend_rows)
    given_ids = {r.get("id") for r in rows}
    left_ids = [r.get("id") for r in pend_rows if r.get("id") not in given_ids and isinstance(r.get("id"), int)]
    next_id = min(left_ids) if left_ids else 0        # 0 = nincs kiadatlan: a kurzor szabadon mehet a kiadottakig
    replies = [{k: r.get(k) for k in _REPLY_KEYS if k in r} for r in rows]
    # KIMENŐ IRÁNY, NAPLÓZÁS-ELŐBB: a kiadás előtt (1) egy kör-bejegyzés a kurzorral — ha van kiadott válasz, VAGY a kurzor
    # eltér a legutóbb naplózott körétől (így a busz-gépen, napló nélkül előreugratott kurzor a következő körben
    # látszik), és (2) válaszonként egy `delivered` bejegyzés; az envelope_sha256 a kiadott dict JCS-hash-e, a távoli fél
    # újraszámolja (bus_notary reconcile). Bármely naplóhiba -> a válaszok NEM mennek ki.
    if notary is not None:
        cur = ab.cursor_of(identity, db=db)
        # a kör-bejegyzés KÖTELEZZE EL MAGÁT a busz audit-láncának fejére —
        # így az összevetéskor kimondható, meddig kell érnie a MÁSIK nyilvántartás exportjának. Az `audit_head()`
        # pont erre készült, és eddig egyetlen hívója sem volt: holt kód volt, most élő horgony.
        # A horgonyt (audit_seq/audit_hash) és a `closes` vállalást a KÖZJEGYZŐ írja bele (bus_notary.record):
        # az író fél szava nem lehet a bizonyíték önmagáról. Itt már csak a strict-ack állapot utazik.
        _anchor = {}
        # 2026-09-16: a strict ack clamp TERMÉK-MÓDBAN alapértelmezés. A menekülő ajtó
        # (AGENT_BUS_STRICT_ACK=0) használata NEM lehet néma — a kör-bejegyzés kimondja, hogy ki van kapcsolva.
        try:
            _sa_active, _sa_off = ab.strict_ack_state(db)
            if _sa_off:
                _anchor = dict(_anchor, strict_ack=0)
        except Exception:
            # (mérve): ez volt az EGYETLEN mechanizmus, ami a kör-bejegyzésbe
            # beírja, hogy a clamp menekülő ajtaja nyitva volt — és `pass`-szal a tény NÉMÁN elveszett, a kör
            # pedig megkülönböztethetetlen lett a SZIGORÚ körtől. A saját kommentünk mondta ki fölötte, hogy
            # „a menekülő ajtó NEM lehet néma". A mérés hiánya harmadik állapot, pont mint a `pending_unknown`.
            _anchor = dict(_anchor, strict_ack_unknown=1)
        _round_logged = bool(replies) or cur != notary.last_round_cursor(identity)
        _round_seq = None
        if _round_logged:
            note(envelope={"identity": identity, "cursor": cur,
                           "reply_sha256": [bus_notary.envelope_hash(x) for x in replies]},
                 recipient=identity, kind="pickup", decision="accepted", reason="cursor=%d replies=%d" % (cur, len(replies)),
                 # A `closes: 1` vállalást a KÖZJEGYZŐ írja bele (bus_notary.record) — az író fél nem hagyhatja el.
                 cursor=(dict({"at": cur, "replies": len(replies), "pending": pending, "next_id": next_id},
                              **({"pending_truncated": 1} if pend_truncated else {}), **_anchor) if pend_ok
                         else dict({"at": cur, "replies": len(replies), "pending_unknown": 1}, **_anchor)))
            _round_seq = (out.get("notary") or {}).get("seq")      # a nyitó bejegyzés seq-e: a zárás EZT nevezi meg
        for x in replies:
            rid = x.get("id")
            note(envelope=x, recipient=identity, kind="pickup", decision="delivered", reason="id=%s" % rid,
                 cursor=({"id": int(rid)} if isinstance(rid, int) and not isinstance(rid, bool) and rid >= 0 else None))
    if replies:                                                # a kiadott posta KÉZBESÍTETT (a kurzor nem mozdul)
        try:
            ab.mark_delivered(identity, [x.get("id") for x in replies], db=db)
        except Exception as e:                                 # az írási hiba NEM néma (mint az ack-ágon)
            note(envelope={"identity": identity, "mark_delivered": "failed"}, recipient=identity, kind="pickup",
                 decision="rejected", reason="mark_delivered_failed: %s" % str(e)[:120])
            # A: ha a jelzés SEM íródik ki, a _NotaryWriteFailed tovább száll -> FAIL-CLOSED válasz,
            # a posta NEM megy ki (a kliens a következő körben újra kéri). Néma kettős hiba nem maradhat.
    # TÁMADÁSI MÁTRIX 2.7 (nyitott sor, most zárva): a kör NYITÓ horgonya a kör ELEJÉN íródik, tehát a kör saját
    # ack-/kiadás-sorait nem köti — egykörös szeleten a busz audit-láncát következetesen újra lehetett láncolni.
    # A ZÁRÓ bejegyzés MINDEN mellékhatás után megy ki, és a horgonyt a KÖZJEGYZŐ számolja bele.
    # Fail-open KIMONDVA: itt már nem lehet fail-closed (a posta kiadva, a `mark_delivered` megtörtént) — ha a
    # záró írás elbukik, azt (a) a válasz `round_close: "failed"` mezője mondja ki a távoli félnek, (b) a
    # reconcile `audit_round_unclosed` soft-eltérésként látja. Néma nem marad.
    # …és CSAK akkor, ha volt NYITÓ kör-bejegyzés: a záró horgony ahhoz párosul, nem önálló zaj.
    if notary is not None and locals().get("_round_logged"):
        try:
            note(envelope={"identity": identity, "round_close": 1, "cursor": ab.cursor_of(identity, db=db)},
                 recipient=identity, kind="round_close", decision="accepted",
                 reason="close replies=%d" % len(replies),
                 # `round_seq`: a zárás MEGNEVEZI, melyik kört zárja (a nem-Claude kar köre: a puszta sorrend
                 # mellett egy máshonnan való zárás egy záratlan kört „lezártnak" mutathatna). Ha az író fél
                 # hazudik róla, a párosítás nem jön létre -> hiányzó zárás, nem hamis zöld.
                 cursor=dict({"at": ab.cursor_of(identity, db=db), "replies": len(replies)},
                             **({"round_seq": int(_round_seq)} if isinstance(_round_seq, int) else {})))
        except Exception:
            out["round_close"] = "failed"
    out["replies"] = replies
    return out


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    import agent_bus as ab
    identity = argv[0] if argv else ""
    if not identity or ab._safe_name(identity) != identity:   # az identitás a force-command-ból jön, és fájlnév-biztos
        print(json.dumps({"error": "no or unsafe identity (must come from the force-command argument)", "processed": False}))
        return 2
    raw = sys.stdin.buffer.read(MAX_BYTES + 1)
    res = exchange(identity, raw)
    print(json.dumps(res, ensure_ascii=False))
    return 2 if "error" in res else 0


if __name__ == "__main__":
    sys.exit(main())
