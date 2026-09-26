#!/usr/bin/env python3
"""bus_ssh_client — the REMOTE machine's side: one exchange round with the bus machine over SSH (v1.2).

    python3 bus_ssh_client.py --target bus@host --local-identity me [--send-to X --body "…" --kind msg]

One round: `ssh <target>` (on the server side the force-command runs only bus_ssh_exchange), on stdin the outgoing
messages + the largest reply id stored in the previous round as `ack`; the replies go onto the LOCAL bus
(recipient = local identity, sender = NAMESPACED: `ssh:<host>~<the sender named by the remote party>`). The namespace is the
boundary: on the server side the identity comes from the force-command argument and the payload's
`from`/`sender` field does not count — on the client side the same boundary was REVERSED, the remote reply's `sender` raw
became the local sender, so the remote machine could write onto the local bus in the name of any LOCAL agent (even the operator).
From now on a remote machine can NEVER write under a local name: the local row's sender is always the composition of the remote target + the named
name, and `/` and every non-[A-Za-z0-9_.-] character are removed from the named name (so the registry's `basename`-based
key resolution cannot fall back to a local name either). The largest stored id lives in a state file →
the same reply never enters the local bus twice, and the server's cursor steps only AFTER successful local storage.

The `ssh` command is swappable (`ssh_cmd`), so the tests run the endpoint with a local fake ssh — the tests
never connect to a real host. Attachments: the `attach_descs` descriptors go chunked from the local store. stdlib-only."""
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
    """The sender name going onto the LOCAL bus for a remote reply: `ssh:<host>~<named>`.
    (2026-09-17): the named name raw became the local sender → the remote machine wrote in a local agent's name.
    The namespace is the client's stated boundary: the remote party chooses the part AFTER `~`, it cannot reach the LOCAL namespace.
    From the named part every non-[A-Za-z0-9_.-] character (so `/`, space, control) becomes `_`, and it is cut to 48
    characters — the registry's key resolution is `basename`-based, so even a `../hub` cannot fall back to the local `hub`.
    An empty/non-string named name → `?` (stated, not silent)."""
    host = str(target or "").rsplit("@", 1)[-1] or "?"
    host = "".join(ch if (ch.isalnum() or ch in "_.-") else "_" for ch in host)[:_CLAIMED_MAX] or "?"
    raw = claimed if isinstance(claimed, str) else ""
    safe = "".join(ch if (ch.isalnum() or ch in "_.-") else "_" for ch in raw)[:_CLAIMED_MAX]
    if not safe or safe.strip(".") == "":
        safe = "?"
    return "ssh:%s~%s" % (host, safe)


def receipts_path(state_dir: str, target: str, local_identity: str) -> str:
    """The remote party's receipt list (JSONL, per round): `bus_notary reconcile` compares it with the bus machine's log."""
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
    """v1.5.2 (2026-09-21): the CLIENT signs the outgoing messages with its own key (`ts`/`sig`/`pubkey` on the message),
    so that the row stored on the bus machine is `signed` in the recipient's product-mode read (by principle the bus machine does not sign the
    remote party's row; and product mode drops a bare row under a name pinned in the registry — on 09-19..21 between the two machines
    every row vanished silently this way). Key: `sign_key`, otherwise `<keys_dir>/<local_identity>.ed25519.key`
    (AGENT_BUS_KEYS_DIR); if there is no key, the message stays unchanged (the server rejects it with a reason if pinned).
    The signed content's `sender` field is the local identity — the server makes the force-command identity the sender,
    so if the two differ, the signature does not verify (that is the intent: one cannot sign in someone else's name)."""
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
        # The outgoing side does NOT normalize on its own EITHER: it calls the same `canonical_text_field`
        # as the byte-image builder and the inbound path. It used to say `or "msg"` here too — the four places only
        # matched BY CHANCE, and when I aligned two with the spec, the other two immediately diverged.
        pre = ab.sign_for_send(key, local_identity, str(m.get("to", "")),
                               ab.canonical_text_field(m.get("body")),
                               topic=ab.canonical_text_field(m.get("topic")),
                               kind=ab.canonical_text_field(m.get("kind")),
                               in_reply_to=m.get("in_reply_to"))
        out.append(dict(m, **pre))
    return out


def exchange(target: str, local_identity: str, messages=None, *, ssh_cmd=None, state_dir=None, db=None,
             attach_descs=None, attach_root=None, timeout: float = 120.0, sign_key=None) -> dict:
    """One exchange round. -> the server's response object + `stored_locally` (the number of replies written to the local bus)."""
    import agent_bus as ab
    import bus_attach
    state_dir = state_dir or os.path.join(os.path.dirname(ab.DB), "remote_state")
    sp = _state_path(state_dir, target, local_identity)
    st = _load_state(sp)
    payload = {"ack": int(st.get("stored_max", 0)), "messages": sign_outgoing(local_identity, messages, sign_key=sign_key)}
    if attach_descs:
        store = bus_attach.Store(attach_root)
        payload["attachments"] = [{"descriptor": d, "chunks": list(store.chunks(d))} for d in attach_descs]
    # receipt: the request line (sent dicts + ack) goes into the file BEFORE SENDING, with a
    # round id; the END of the round writes the outcome as a new line (append-only): not-sent (provably did not go out),
    # unknown (may have gone out, the reply did not come / was faulty), delivered (the server replied; with the received replies and the anchor).
    # reconcile accuses only from a delivered round; unknown is a separate "unresolved" list, not-sent is not an accusation.
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
    except OSError as e:                                        # ssh did not even start
        _receipt({"phase": "outcome", "outcome": "not-sent", "reason": str(e)[:200]})
        return {"error": "ssh could not start: %s" % e}
    except subprocess.TimeoutExpired:
        _receipt({"phase": "outcome", "outcome": "unknown", "reason": "timeout"})
        raise
    try:
        out_txt = proc.stdout.decode("utf-8", "replace")
        res = json.loads(out_txt) if out_txt.strip() else None   # C1: empty output is NOT a valid response
    except ValueError:
        res = None
    if not isinstance(res, dict) or "error" in res:
        # ssh 255 = the connection was not established (the endpoint itself exits with 0/2) -> not-sent; other non-JSON -> unknown.
        # a valid JSON object response (even {"error":...}) = the request PROVABLY arrived
        # -> reached (reconcile accuses as for delivered). The round outcome answers the question "did it provably arrive".
        # THREE levels. proven: delivered/reached · presumed: timeout, rc 255 + non-JSON,
        # processed:false (the accused's unsigned word) · ruled out: OSError (ssh did not even start) -> only that is not-sent.
        claimed = isinstance(res, dict) and res.get("processed") is False
        if claimed:
            outcome = "unknown"
        elif isinstance(res, dict):
            outcome = "reached"
        else:                            # the label stays (not-sent / unknown), but rc 255 is NOT ruled out: reconcile treats
            outcome = "not-sent" if proc.returncode == 255 else "unknown"   # a not-sent carrying an rc as PRESUMED
        row = {"phase": "outcome", "outcome": outcome, "rc": proc.returncode,
               "error": (res or {}).get("error") if isinstance(res, dict) else "non-JSON reply"}
        if claimed:
            row["peer_claimed_unprocessed"] = True
        if isinstance(res, dict):        # replies/anchor that came ALONGSIDE the error also go into the receipt
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
    # AGENT_BUS_AUTO_SIGN=0 used to be set here PROCESS-GLOBALLY, and never restored — every later send of a longer-lived
    # caller (e.g. the CI sentinel) stayed unsigned. The opt-out is now PER CALL: `sign_key=False`.
    for r in res.get("replies") or []:
        rid = r.get("id")
        if not isinstance(rid, int) or rid <= top:
            continue                                            # already stored (previous round, interrupted before the ack) → dedupe
        try:
            # the sender is NAMESPACED — the remote machine cannot choose a local name (see remote_sender_name)
            ab.send(remote_sender_name(target, r.get("sender")), local_identity, str(r.get("body", "")),
                    topic=str(r.get("topic") or ""), kind=str(r.get("kind") or "msg"), db=db, sign_key=False)
            stored += 1
        except ValueError:
            pass                                                # the local bus's rule (e.g. a bad sds frame) → not stored
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
