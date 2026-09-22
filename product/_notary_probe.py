#!/usr/bin/env python3
"""Chapter 2 of the evidence envelope: build a fresh notary chain with the SHIPPED code, attack it, and require the
shipped verifier to catch every attack. Run from the installed tree; prints one JSON object per probe and exits 1 if
any probe did not behave as claimed. stdlib + cryptography."""
import copy
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import bus_notary as bn  # noqa: E402

PLAIN = "SEALED-BUS-PROBE-PLAINTEXT-DO-NOT-LOG"
out, failed = [], 0


def probe(name, expectation, ok, detail=""):
    global failed
    out.append({"probe": name, "expected": expectation, "ok": bool(ok), "detail": str(detail)[:200]})
    if not ok:
        failed += 1


def errs_at(recs, pub):
    rep = bn.verify(recs, trusted_pub=pub)
    return rep, [e.get("error", "") for e in rep["errors"]]


def main():
    if not bn.HAVE_CRYPTO:
        print(json.dumps({"chapter": "notary", "status": "SKIP", "reason": "python3 cryptography is not installed"}))
        return 2
    with tempfile.TemporaryDirectory() as t:
        log = os.path.join(t, "chain.jsonl")
        seed, pub = bn.keypair()
        n = bn.Notary(log, seed=seed, checkpoint_every=4)
        for i in range(8):
            n.record(envelope={"i": i, "body": PLAIN}, sender_identity="probe", sender_auth="ssh-key",
                     recipient="hub", kind="msg", decision="accepted" if i % 3 else "rejected", reason="")
        clean = bn.export(log, 1)
        rep, _ = errs_at(clean, pub)
        probe("clean chain verifies and is trusted", "ok:true trusted:true",
              rep["ok"] and rep["trusted"], "ok=%s trusted=%s" % (rep["ok"], rep["trusted"]))
        probe("log holds no plaintext", "the probe body never appears in the log file",
              PLAIN not in open(log, encoding="utf-8").read())

        edited = copy.deepcopy(clean)
        for r in edited:
            if r.get("type") == "entry" and r["seq"] == 3:
                r["decision"] = "accepted" if r["decision"] == "rejected" else "rejected"
        rep, e = errs_at(edited, pub)
        probe("edited entry", "error at that seq", not rep["ok"] and any("rewritten" in x for x in e), e[:1])

        rehashed = copy.deepcopy(clean)
        for r in rehashed:
            if r.get("type") == "entry" and r["seq"] == 3:
                r["recipient"] = "attacker"
                r["entry_hash"] = bn.entry_hash(r)
        rep, e = errs_at(rehashed, pub)
        probe("entry re-hashed after editing", "the next entry's chain link breaks", not rep["ok"], e[:1])

        deleted = [r for r in copy.deepcopy(clean) if not (r.get("type") == "entry" and r["seq"] == 5)]
        rep, e = errs_at(deleted, pub)
        probe("entry deleted", "gap reported", not rep["ok"] and any("gap" in x for x in e), e[:1])

        reordered = copy.deepcopy(clean)
        idx = [i for i, r in enumerate(reordered) if r.get("type") == "entry" and r["seq"] in (2, 3)]
        reordered[idx[0]], reordered[idx[1]] = reordered[idx[1]], reordered[idx[0]]
        rep, e = errs_at(reordered, pub)
        probe("entries reordered", "reordered / chain broken", not rep["ok"], e[:1])

        forged = copy.deepcopy(clean)
        for r in forged:
            if r.get("type") == "checkpoint":
                r["ts_ms"] += 1
        rep, e = errs_at(forged, pub)
        probe("checkpoint signature forged", "forged checkpoint signature",
              not rep["ok"] and any("forged" in x for x in e), e[:1])

        other_seed, _ = bn.keypair()
        bn.Notary(log, seed=other_seed).checkpoint()
        rep, e = errs_at(bn.export(log, 1), pub)
        probe("checkpoint signed by another key", "untrusted key",
              not rep["ok"] and any("untrusted" in x for x in e), e[:1])

        log2 = os.path.join(t, "fresh.jsonl")
        seed2, pub2 = bn.keypair()
        n2 = bn.Notary(log2, seed=seed2, checkpoint_every=100)
        n2.record(envelope={"x": 1}, sender_identity="probe", sender_auth="ssh-key", recipient="hub", kind="msg",
                  decision="accepted")
        rep2 = bn.verify(bn.export(log2, 1), trusted_pub=pub2)
        probe("slice with no verified checkpoint", "ok but NOT trusted",
              rep2["ok"] and not rep2["trusted"], "trusted=%s tail=%s" % (rep2["trusted"], rep2["unverified_tail"]))

        cmp_rep = bn.compare(clean, bn.export(log2, 1))
        probe("two divergent exports compared", "not 'same', and 'nothing to compare' is not 'fine'",
              cmp_rep["same"] is not True, json.dumps(cmp_rep)[:120])

        n.record(envelope={"ack": 2}, sender_identity="probe", sender_auth="ssh-key", recipient="probe", kind="ack",
                 decision="accepted", reason="cursor 0->9 (ack 2)")
        rep3 = bn.verify(bn.export(log, 1), trusted_pub=pub)
        probe("ack whose cursor target exceeds max(from, ack)", "reported as a violation",
              bool(rep3["ack_target_violations"]), rep3["ack_target_violations"][:1])
    for row in out:
        print(json.dumps(row, ensure_ascii=False))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
