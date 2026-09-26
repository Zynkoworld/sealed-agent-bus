#!/usr/bin/env python3
"""sweep_log_probe.py — a field sweep of the NOTARY LOG as a standing sentinel.

WHY: on the capsule2 side the sweep (deleting every field / `null` / empty / type swap) repeatedly produced
findings a hand-written probe would not have found; on the bus side the same method revealed two tracebacks
in `reconcile` (`envelope_sha256` deleted -> `KeyError`, `reason: null` -> `TypeError`). But such a measurement
is only worth something as long as someone runs it — so this file runs in CI on every push.

What it measures: it builds a REAL round (mail -> delivery -> ack) with the notary and the bus audit table, then
goes through the forgeries for every entry field, and requires that

  * a forgery does NOT stay silently green (the hash chain or the shape gate states it), and
  * there is NEVER a traceback — the OTHER party's export is untrusted input, a traceback is not a diagnosis.

rc=0 green · rc=1 silent or traceback · rc=2 usage error.
"""
from __future__ import annotations

import contextlib
import copy
import json
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)


# In the CONSISTENT WRITER model (re-chaining AFTER the forgery) the `cursor` sub-fields measured as NOT checked.
# "where silence is fine, a stated, named list must say
# that the field is not checked." This is that list. A sub-field that is NOT in it and still stays silent is a FINDING.
# IMPORTANT, what the measurement showed: these fields are NOT bound because anyone reads them, but by the SIGNATURE
# — the same sweep on an export containing a SIGNED checkpoint gives 0 silent, because the writer can re-chain, but
# cannot re-sign the notary's checkpoint.
CURSOR_UNCHECKED = {
    "at":             "the cursor position — bound by the bus audit row's from/to pair, not by the round entry's",
    "id":             "the DELIVERED message's id on the `delivered` row — compared with the receipts, not on its own",
    "ack":            "the round's ack target — bound by the audit row's `to_id`",
    "from":           "the ack's starting cursor — bound by the audit row's `from_id`",
    "to":             "the ack's target cursor — bound by the audit row's `to_id`",
    "pending":        "only makes a claim RELATIVE to `replies` (`_claims_no_skip`)",
    "replies":        "the same relation from the other side",
    "next_id":        "the first undelivered — a claim only relative to the ack target",
    "round_seq":      "the closing anchor pointing back to the round — bound by ORDER, not by value",
    "audit_hash":     "the opening anchor's hash — bound by the `by_seq` comparison, if the export reaches that far",
    "audit_end_hash": "the closing anchor's hash — the same",
}


def _hex(x):
    return x.hex() if isinstance(x, (bytes, bytearray)) else str(x)


def build_round(t, mode="dev"):
    """A real round: 3 messages, delivery, ack — the log and the bus audit table are both created.

    (2026-09-17): until now the round was built ONLY in dev mode (the probe's own env), and in product mode it did not
    go red but blew up (`max()` on an empty list: enforcement dropped the unsigned rows) — the sentinel running
    in CI did not measure the PRODUCT configuration, and did not say so. Now the round is built in BOTH modes: in product
    mode the `hub` sender auto-signs with the key pinned in the registry (root, 0600), so enforcement lets it through.
    The modes live in ONE tmp directory, with separate DB/log/store paths (`agent_bus.KEYS_DIR` is fixed at import)."""
    keys = os.path.join(t, "keys")
    os.environ.update({"AGENT_BUS_DB": os.path.join(t, "bus_%s.db" % mode), "AGENT_BRIDGE_DIR": t,
                       "AGENT_BUS_DIR": t, "AGENT_BUS_MODE": mode, "AGENT_BRIDGE_INBOX": os.path.join(t, "inbox"),
                       "AGENT_BUS_KEYS_DIR": keys, "AGENT_WAKE_DIR": os.path.join(t, "wake"),
                       "AGENT_BUS_AUTO_SIGN": "1" if mode == "product" else "0"})
    import agent_bus as ab
    import bus_notary as bn
    import bus_ssh_exchange as ex
    db, log = os.environ["AGENT_BUS_DB"], os.path.join(t, "n_%s.jsonl" % mode)
    if mode == "product":
        # `hub`'s pinned key: registry pub + guarded seed (root-owned, 0600, the directory not group/world-writable)
        os.makedirs(keys, mode=0o700, exist_ok=True)
        os.chmod(keys, 0o700)
        hseed, hpub = bn.keypair()
        with open(os.path.join(keys, "hub.pub"), "w", encoding="utf-8") as f:
            f.write(_hex(hpub))
        kp = os.path.join(keys, "hub.ed25519.key")
        with open(kp, "w", encoding="utf-8") as f:
            f.write(_hex(hseed))
        os.chmod(kp, 0o600)
    seed, _pub = bn.keypair()
    # DENSE checkpoints: with the earlier `checkpoint_every=50`, NOT A SINGLE checkpoint got into the 3-message round,
    # so the sweep never even saw the SIGNED row. It was my own sentinel's blind spot (2026-09-16).
    notary = bn.Notary(log, seed=seed, checkpoint_every=2, db=db)
    for i in range(3):
        ab.send("hub", "remote1", "ki-%d" % i, db=db, mirror=False)
    r1 = ex.exchange("remote1", json.dumps({}), db=db, attach_root=os.path.join(t, "att"), notary=notary)
    if mode == "product":
        # the product round measures product ONLY if enforcement was really live AND the replies came through signed —
        # otherwise the "green" would be a dev round with a product label (exactly its error class, one layer deeper)
        import bus_enforce as enf
        if enf.mode(db=db) != "product":
            raise RuntimeError("the product round did not run in product mode (mode=%r)" % enf.mode(db=db))
        # the reply projection (_REPLY_KEYS) carries no sig — we measure the BUS rows, not the projection
        rows_p = ab.recv("remote1", mark=False, db=db)
        auth = [ab.verify_sender(r) for r in rows_p]
        if not r1["replies"] or not rows_p or any(a != "signed" for a in auth):
            raise RuntimeError("the product round's rows are not 'signed' (replies=%d, auth=%s) — enforcement cannot be measured"
                               % (len(r1["replies"]), auth))
    top = max(m["id"] for m in r1["replies"])
    ex.exchange("remote1", json.dumps({"ack": top}), db=db, attach_root=os.path.join(t, "att"), notary=notary)
    if mode == "product":
        # the real cause: the exchange disabled auto-sign PROCESS-GLOBALLY — a LATER send in the same
        # process stayed unsigned. So a send AFTER the exchange must also be 'signed' (mutant-sensitive).
        ab.send("hub", "remote1", "post-exchange", db=db, mirror=False)
        after = ab.recv("remote1", mark=False, db=db)
        if not after:
            raise RuntimeError("product mode DROPPED the send AFTER the exchange (unsigned) — the exchange corrupted process "
                               "state (AGENT_BUS_AUTO_SIGN disabled globally)")
        last = after[-1]
        if ab.verify_sender(last) != "signed":
            raise RuntimeError("a send AFTER the exchange is not 'signed' (%s) — the exchange corrupted process state"
                               % ab.verify_sender(last))
    exp = bn.export(log, 1)
    c = ab._conn(db)
    try:
        rows = [dict(x) for x in c.execute(
            "SELECT seq,ts,agent,op,from_id,to_id,skipped_undelivered,prev_row_hash,row_hash "
            "FROM cursor_audit WHERE agent='remote1' ORDER BY id")]
    finally:
        c.close()
    receipts = [{"phase": "request", "sent": [], "ack": top, "received": r1["replies"], "round": "r1"},
                {"phase": "outcome", "outcome": "delivered", "round": "r1", "rc": 0}]
    return bn, exp, rows, receipts


def sweep(t, probe_mode) -> int:
    """The full sweep in ONE mode (dev | product). rc=0 green, rc=1 silent/traceback."""
    with contextlib.nullcontext():
        bn, exp, rows, receipts = build_round(t, probe_mode)

        def run(entries):
            try:
                rep = bn.reconcile(copy.deepcopy(entries), "remote1", copy.deepcopy(receipts),
                                   strict=True, bus_audit=copy.deepcopy(rows))
                return rep["ok"]
            except Exception as e:                      # a traceback maga a lelet
                return "CRASH:%s" % e.__class__.__name__

        if run(exp) is not True:
            print("sweep_log_probe: the UNTOUCHED export is not green — the probe cannot measure")
            return 1
        # EVERY row type, not only `entry`: the `checkpoint` carries the notary's SIGNATURE, and until now
        # no shape gate at all ran on it. So the sweep goes through the fields per type.
        keys_by_type = {}
        for e in exp:
            ty = e.get("type")
            if ty:
                keys_by_type.setdefault(ty, set()).update(e)
        if "checkpoint" not in keys_by_type:
            print("sweep_log_probe: the corpus has NO checkpoint row — the probe does not measure the signed row")
            return 1
        # `claimed_ts_ms` REALLY is None on most entries: `null` changes nothing there
        noop = {("entry", "claimed_ts_ms", "null"),   # (row type, field, MODE) — a list value cannot be a key
                ("entry", "type", "str"), ("checkpoint", "type", "str")}   # rewriting `type` is ANOTHER row type
        silent, crashed, n = [], [], 0
        for ty in sorted(keys_by_type):
          for k in sorted(keys_by_type[ty]):
            for mode, val in (("delete", None), ("null", None), ("zero", 0), ("str", "X"), ("empty", [])):
                ents, touched = copy.deepcopy(exp), 0
                for e in ents:
                    if e.get("type") != ty or k not in e:
                        continue
                    if mode == "delete":
                        e.pop(k)
                        touched += 1
                    elif e[k] != val:
                        e[k] = val
                        touched += 1
                if not touched or (ty, k, mode) in noop:
                    continue
                n += 1
                res = run(ents)
                if res is True:
                    silent.append((ty, k, mode, touched))
                elif isinstance(res, str):
                    crashed.append((ty, k, mode, res))
        print("sweep_log_probe: %d tamper | silent=%d crash=%d" % (n, len(silent), len(crashed)))
        for ty, k, mode, c in silent[:10]:
            print("  - SILENT: %s.%s mode=%s (%d rows) — the report stayed green" % (ty, k, mode, c))
        for ty, k, mode, e in crashed[:10]:
            print("  - CRASH:  %s.%s mode=%s -> %s — a traceback is not a diagnosis" % (ty, k, mode, e))
        if silent or crashed:
            return 1
        # ── phase 2: the `cursor` SUB-FIELDS, in the CONSISTENT WRITER model ─────────────────────────────
        # MEDIUM (a)+(b): the sweep above goes over the entry's TOP-LEVEL fields, and the
        # diagnosis is often given by the hash guard — but whoever WRITES the log also computes the chain.
        import bus_notary as _bn

        def _rechain(ents):
            prev, seq = "0" * 64, 0
            for e in ents:
                if e.get("type") != "entry":
                    continue
                seq += 1
                e["seq"], e["prev_hash"] = seq, prev
                e["entry_hash"] = _bn.entry_hash({k: v for k, v in e.items()
                                                  if k not in ("type", "entry_hash")})
                prev = e["entry_hash"]
            return ents

        subs = set()
        for e in exp:
            if e.get("type") == "entry" and isinstance(e.get("cursor"), dict):
                subs |= set(e["cursor"])
        # We measure TWO slices, because their difference IS the finding:
        #   (a) the FULL export — it contains a SIGNED checkpoint: the writer can re-chain, but cannot re-SIGN;
        #   (b) a slice WITHOUT A SIGNATURE (checkpoint rows removed) — this is one arm's corpus, and here it shows
        #       what someone ACTUALLY reads, and what was bound only by the signature.
        # If we measured only (a), the stated list would never speak up — we would skip exactly the dangerous case.
        slices = [("with a signed checkpoint", list(exp)),
                  ("UNSIGNED slice", [e for e in exp if e.get("type") != "checkpoint"])]
        for _label, _base in slices:
          if run(_rechain(copy.deepcopy(_base))) is not True:
            print("sweep_log_probe: the RE-CHAINED, untouched %s is not green — phase 2 cannot measure" % _label)
            return 1
        c_silent, c_crash, c_n = [], [], 0
        _base = slices[1][1]                     # the measurement decides on the UNSIGNED slice (the stricter case)
        for k in sorted(subs):
            for mode, val in (("delete", None), ("null", None), ("zero", 0), ("str", "X"), ("empty", [])):
                ents, touched = copy.deepcopy(_base), 0
                for e in ents:
                    cur = e.get("cursor")
                    if e.get("type") != "entry" or not isinstance(cur, dict) or k not in cur:
                        continue
                    if mode == "delete":
                        cur.pop(k)
                        touched += 1
                    elif cur[k] != val:
                        cur[k] = val
                        touched += 1
                if not touched:
                    continue
                c_n += 1
                res = run(_rechain(ents))
                if res is True:
                    c_silent.append((k, mode))
                elif isinstance(res, str):
                    c_crash.append((k, mode, res))
        undeclared = sorted({k for k, _ in c_silent} - set(CURSOR_UNCHECKED))
        # …and the same sweep on the SIGNED slice: here we expect 0 silent, because the checkpoint cannot be re-signed
        s_silent, s_n = [], 0
        for k in sorted(subs):
            for mode, val in (("delete", None), ("null", None), ("zero", 0), ("str", "X"), ("empty", [])):
                ents, touched = copy.deepcopy(exp), 0
                for e in ents:
                    cur = e.get("cursor")
                    if e.get("type") != "entry" or not isinstance(cur, dict) or k not in cur:
                        continue
                    if mode == "delete":
                        cur.pop(k)
                        touched += 1
                    elif cur[k] != val:
                        cur[k] = val
                        touched += 1
                if not touched:
                    continue
                s_n += 1
                if run(_rechain(ents)) is True:
                    s_silent.append((k, mode))
        print("sweep_log_probe/cursor (consistent writer):")
        print("   with a SIGNED checkpoint: %d forgeries | silent=%d   <- the backing is the SIGNATURE, not the check"
              % (s_n, len(s_silent)))
        print("   on the UNSIGNED slice:    %d forgeries | silent=%d (%d fields) crash=%d"
              % (c_n, len(c_silent), len({k for k, _ in c_silent}), len(c_crash)))
        if s_silent:
            for k, mode in s_silent[:8]:
                print("  - SILENT: cursor.%s mode=%s on the SIGNED slice — not even the signature binds it" % (k, mode))
            return 1
        for k, mode, e in c_crash[:8]:
            print("  - CRASH:  cursor.%s mode=%s -> %s — a traceback is not a diagnosis" % (k, mode, e))
        for k in undeclared:
            print("  - SILENT: cursor.%s — NOT on the stated (unchecked) list" % k)
        if undeclared or c_crash:
            return 1
        for k in sorted({k for k, _ in c_silent}):
            print("      unchecked (stated): cursor.%-16s %s" % (k, CURSOR_UNCHECKED[k]))
        print("PASS (mode=%s) — no notary entry field can be dropped or mistyped without a diagnosis, and every "
              "silent cursor sub-field is DECLARED as unchecked (not hidden)." % probe_mode)
        return 0


MODES = ("dev", "product")


def main(argv=None) -> int:
    """the verdict holds only for the MEASURED modes. Both modes run; if a round is not even built, that is RED and stated
    (not a traceback, not a silent 'dev only'). 'ALL PASS' only if both dev AND product are green."""
    rc = 0
    with tempfile.TemporaryDirectory() as t:
        for mode in MODES:
            print("=== sweep_log_probe: mode=%s ===" % mode)
            try:
                r = sweep(t, mode)
            except Exception as e:                      # building the round is itself a measurement: its failure is a finding, not a traceback
                print("sweep_log_probe: the %s-mode round was NOT BUILT (%s: %s) — the verdict does NOT cover this mode"
                      % (mode, e.__class__.__name__, e))
                r = 1
            rc = max(rc, r)
    if rc == 0:
        print("ALL PASS — measured in BOTH modes: %s" % ", ".join(MODES))
    else:
        print("FAIL — at least one mode is red or unmeasured (see above); the verdict covers only the green modes")
    return rc


if __name__ == "__main__":
    sys.exit(main())
