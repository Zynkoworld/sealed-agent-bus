#!/usr/bin/env python3
"""sce_hook — a STABLE HOOK POINT for the Silent Consensus Engine (v1.2). There is NO engine code here.

SCE lives in a separate project (byte-match of three independent implementations + valid derivation →
ACCEPT / REJECT / ABORT; without communication). The bus ONLY transports the arms' sds-envelopes, and at this point
hands them to a decider wired in by the operator:

    AGENT_BUS_SCE_DECIDER=module:function      # e.g. my_bus_adapter:decide  (the bus does not bring or vendor it)

Contract:
    decide(envelopes: list[dict]) -> {"verdict": "ACCEPT" | "REJECT" | "ABORT",...arbitrary audit fields}

    envelopes items: {"id", "sender", "body", "sds"} — body is the text of the framed SDS envelope, `sds` is the bus's v1.1
    check label (valid / invalid(<reason>) / unsigned / unverifiable(<reason>)). The decider itself decides what it accepts.

Behaviour:
- No decider wired in → `decide()` returns None: the bus makes NO decision (there is no "default consensus").
- The decider's exception, non-dict result or unknown verdict → {"verdict": "ABORT", "reason": …} (fail-closed).
- There is deliberately NO "consensus strength" (0–1) or meaning-vector blending: the average of similar opinions
  is not evidence — the verdict comes from byte-match and derivation, at the decider."""
from __future__ import annotations

import importlib
import json
import os

VERDICTS = ("ACCEPT", "REJECT", "ABORT")
ENV = "AGENT_BUS_SCE_DECIDER"


def load_decider(spec: str | None = None):
    spec = os.environ.get(ENV, "") if spec is None else spec
    if not spec:
        return None
    mod, _, fn = spec.partition(":")
    if not mod or not fn:
        raise ValueError("%s must be module:function" % ENV)
    return getattr(importlib.import_module(mod), fn)


def decide(envelopes: list, *, decider=None, spec: str | None = None):
    """-> the decider's verdict (dict) or None if no decider is wired in."""
    try:
        fn = decider or load_decider(spec)
    except (ImportError, AttributeError, ValueError) as e:
        return {"verdict": "ABORT", "reason": "decider unavailable: %s" % e}
    if fn is None:
        return None
    try:
        res = fn(list(envelopes))
    except Exception as e:                                     # noqa: BLE001 - any decider error = ABORT
        return {"verdict": "ABORT", "reason": "decider raised: %s" % type(e).__name__}
    if not isinstance(res, dict) or res.get("verdict") not in VERDICTS:
        return {"verdict": "ABORT", "reason": "decider returned no valid verdict"}
    return res


def envelopes_from_rows(rows: list) -> list:
    """The sds-envelopes among the rows of `recv(verify_sds=True)`, in the decider's format."""
    return [{"id": r.get("id"), "sender": r.get("sender"), "body": r.get("body"), "sds": r.get("sds")}
            for r in rows if r.get("kind") == "sds-envelope"]


# ── v1.4: bus row → arm envelope mapping (SCE end to end) ─────────────────────────────────────────
ARM_SCHEMA = "sce-arm-envelope/v1"


def arm_envelope_of(env: dict, *, require_valid: bool = True):
    """An `envelopes_from_rows` item → the arm envelope (dict) or None.
    MAPPING (documented contract): the bus `sds-envelope` body is the framed SDS pair `{record, envelope}`; the
    **record's `payload` field carries the `sce-arm-envelope/v1` object** (schema, arm, seed, candidate_package,
    reference_package, derive_hash[, candidate_hash]). So the SDS envelope's signature binds the arm envelope too.
    `require_valid`: only a row the bus labelled `valid` (signed, admitted) can give an arm envelope — from an
    unsigned/forged row there is NO arm (the decider then ABORTs on a missing arm, not "two arms are enough")."""
    if require_valid and not str(env.get("sds") or "").startswith("valid"):
        return None
    body = env.get("body")
    try:
        framed = json.loads(body) if isinstance(body, str) else body
    except ValueError:
        return None
    if not isinstance(framed, dict) or not isinstance(framed.get("record"), dict):
        return None
    payload = framed["record"].get("payload")
    if not isinstance(payload, dict) or payload.get("schema") != ARM_SCHEMA:
        return None
    return payload


def decide_rows(rows: list, *, decider=None, spec: str | None = None, require_valid: bool = True):
    """recv(verify_sds=True) rows → arm envelopes → decider. None if no decider is wired in."""
    arms = [a for a in (arm_envelope_of(e, require_valid=require_valid) for e in envelopes_from_rows(rows)) if a is not None]
    return decide(arms, decider=decider, spec=spec)

