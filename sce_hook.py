#!/usr/bin/env python3
"""sce_hook — STABIL CSATLAKOZÁSI PONT a Silent Consensus Engine-hez (v1.2). Motor-kód NINCS itt.

Az SCE egy külön projektben él (három független implementáció bájt-egyezése + érvényes leszármazás →
ACCEPT / REJECT / ABORT; kommunikáció nélkül). A busz CSAK szállítja a karok sds-envelope-jait, és ezen a ponton
átadja őket egy operátor által bekötött döntőnek:

    AGENT_BUS_SCE_DECIDER=modul:függvény      # pl. my_bus_adapter:decide  (a busz nem hozza, nem vendorolja)

Szerződés:
    decide(envelopes: list[dict]) -> {"verdict": "ACCEPT" | "REJECT" | "ABORT",...tetszőleges audit-mezők}

    envelopes elemei: {"id", "sender", "body", "sds"} — a body a keretezett SDS-boríték szövege, a `sds` a busz v1.1
    ellenőrző címkéje (valid / invalid(<ok>) / unsigned / unverifiable(<ok>)). A döntő maga dönti el, mit fogad el.

Viselkedés:
- Nincs bekötött döntő → `decide()` None-t ad: a busz NEM hoz döntést (nincs „alapértelmezett konszenzus").
- A döntő kivétele, nem-dict eredménye vagy ismeretlen verdiktje → {"verdict": "ABORT", "reason": …} (fail-closed).
- Szándékosan NINCS „konszenzus-erősség" (0–1) vagy jelentés-vektoros összeolvasztás: hasonló vélemények
  átlaga nem bizonyíték — a verdiktet bájt-egyezés és leszármazás adja, a döntőnél."""
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
    """-> a döntő verdiktje (dict) vagy None, ha nincs döntő bekötve."""
    try:
        fn = decider or load_decider(spec)
    except (ImportError, AttributeError, ValueError) as e:
        return {"verdict": "ABORT", "reason": "decider unavailable: %s" % e}
    if fn is None:
        return None
    try:
        res = fn(list(envelopes))
    except Exception as e:                                     # noqa: BLE001 - bármely döntő-hiba = ABORT
        return {"verdict": "ABORT", "reason": "decider raised: %s" % type(e).__name__}
    if not isinstance(res, dict) or res.get("verdict") not in VERDICTS:
        return {"verdict": "ABORT", "reason": "decider returned no valid verdict"}
    return res


def envelopes_from_rows(rows: list) -> list:
    """A `recv(verify_sds=True)` sorai közül az sds-envelope-ok a döntő formátumában."""
    return [{"id": r.get("id"), "sender": r.get("sender"), "body": r.get("body"), "sds": r.get("sds")}
            for r in rows if r.get("kind") == "sds-envelope"]


# ── v1.4: a busz-sor → kar-boríték leképezés (SCE végponttól végpontig) ─────────────────────────────────────────
ARM_SCHEMA = "sce-arm-envelope/v1"


def arm_envelope_of(env: dict, *, require_valid: bool = True):
    """Egy `envelopes_from_rows` elem → a kar-boríték (dict) vagy None.
    LEKÉPEZÉS (dokumentált szerződés): a busz `sds-envelope` body-ja a keretezett SDS pár `{record, envelope}`; a
    **record `payload` mezője hordozza a `sce-arm-envelope/v1` objektumot** (schema, arm, seed, candidate_package,
    reference_package, derive_hash[, candidate_hash]). Az SDS-boríték aláírása így a kar-borítékot is köti.
    `require_valid`: csak a busz által `valid`-nak címkézett (aláírt, beengedett) sor adhat kar-borítékot — egy
    aláíratlan/hamis sorból NINCS kar (a döntő ilyenkor hiányzó karra ABORT-ol, nem „két kar is elég")."""
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
    """recv(verify_sds=True) sorai → kar-borítékok → döntő. None, ha nincs döntő bekötve."""
    arms = [a for a in (arm_envelope_of(e, require_valid=require_valid) for e in envelopes_from_rows(rows)) if a is not None]
    return decide(arms, decider=decider, spec=spec)

