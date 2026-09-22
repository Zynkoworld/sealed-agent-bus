#!/usr/bin/env python3
"""sds_envelope — SDS bizonyítékos boríték a buszon (a partner-kar három additív lépése, 2026-09-14). Stdlib + opcionális cryptography.

A busz SZÁLLÍT és ÉBRESZT; az SDS (capsule2-spec, capsule-sync v2) megmondja, mi egy érvényes, bizonyítható üzenet.
Ez a modul a kettő közti híd — NEM az SDS referencia-verifikátora, és nem pótolja a két kar kereszt-ellenőrzését:

1. `send --kind sds-envelope`: a body egy keretezett pár `{"record": …, "envelope": …}` (SPEC §5.5 „Combined framing").
   Küldéskor csak a SZERKEZET kötött (check_framed_shape) — hibás keret nem kerül a buszra.
2. `recv --verify-sds`: soronként `valid | invalid(<ok>) | unsigned | unverifiable(<ok>)`.
   - Ha az AGENT_BUS_SDS_VALIDATOR / CAPSULE2_SDS_VALIDATOR env `modul:függvény`-t nevez meg, AZ dönt
     (pl. a capsule2 referencia-verifikátor köré írt adapter). Hívás: fn(framed_dict, context_dict) → (status, ok) | status.
   - Különben a beépített MINIMÁLIS ellenőrzés fut (lent), szűk JCS-profillal.
3. Kormányzás-híd: a busz `keys/<sender>.pub` registry-je köti a feladót a kulcshoz; egy helyi admission-fájl
   mondja meg, ki lehet feladó és milyen org/role-lal. Nem beengedett feladó → invalid(not-admitted);
   a registry-kulcs ≠ a beengedett issuer → invalid(key-mismatch).

Admission-fájl (a busz HELYI nézete a §5.4 admitted-set kötésről; NEM a JOINT genezis-lánc ellenőrzése):
  {"config_id": "sha256:<64hex>", "domain_hash": "<64hex>" (opcionális),
   "admitted": [{"sender": "<busz-identitás>", "issuer": "<ed25519 pubkey 64hex>", "org": "...", "role": "..."}]}
"""
from __future__ import annotations

import hashlib
import importlib
import json
import os
import re
import unicodedata

KIND = "sds-envelope"
DOM_AUTH = b"capsule-sync/auth/v1"                         # SPEC §5: az EGY domain-szeparációs konstans
_ENVELOPE_KEYS = {"record_id", "config_id", "domain", "domain_hash", "epoch", "sigs"}   # SPEC §5.5: zárt objektum
_DOMAIN_KEYS = {"project", "stream", "repo"}
_SLUG = re.compile(r"^[a-z0-9._:-]{1,64}$")
_H64 = re.compile(r"^[0-9a-f]{64}$")
_SHA = re.compile(r"^sha256:[0-9a-f]{64}$")
_H128 = re.compile(r"^[0-9a-f]{128}$")
_SAFE_INT = 2 ** 53 - 1

try:
    from cryptography.hazmat.primitives.asymmetric import ed25519 as _ed
    HAVE_CRYPTO = True
except Exception:                                           # pragma: no cover - környezet-függő
    HAVE_CRYPTO = False


# ── SPEC §1: kanonikus forma (RFC 8785 JCS profil — szűk: egész számok, sztringek, literálok, tömbök, objektumok) ──
def _jcs_str(s):
    out = ['"']
    for ch in s:
        o = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif ch in "\b\t\n\f\r":
            out.append({"\b": "\\b", "\t": "\\t", "\n": "\\n", "\f": "\\f", "\r": "\\r"}[ch])
        elif o < 0x20:
            out.append("\\u%04x" % o)
        else:
            out.append(ch)                                  # U+007F és minden más szó szerint; nincs normalizálás
    out.append('"')
    return "".join(out)


def jcs(value):
    """Kanonikus UTF-8 bájtok. Objektum-kulcsok UTF-16 kódegység-sorrendben; float → ValueError (a profil csak egészet ismer)."""
    def enc(v):
        if v is None:
            return "null"
        if v is True:
            return "true"
        if v is False:
            return "false"
        if isinstance(v, int):
            if not (-_SAFE_INT <= v <= _SAFE_INT):
                raise ValueError("integer outside safe range")
            return str(v)
        if isinstance(v, float):
            raise ValueError("non-integer number")
        if isinstance(v, str):
            return _jcs_str(v)
        if isinstance(v, list):
            return "[" + ",".join(enc(x) for x in v) + "]"
        if isinstance(v, dict):
            items = sorted(v.items(), key=lambda kv: kv[0].encode("utf-16-be"))
            return "{" + ",".join(_jcs_str(k) + ":" + enc(x) for k, x in items) + "}"
        raise ValueError("unsupported JSON type")
    return enc(value).encode("utf-8")


def record_id_of(record):
    """SPEC §2: record_id = "sha256:" + hex(SHA256(JCS(record MINUS top-level record_id)))."""
    body = {k: v for k, v in record.items() if k != "record_id"}
    return "sha256:" + hashlib.sha256(jcs(body)).hexdigest()


# ── 1. lépés: a keret szerkezete (küldéskor) ─────────────────────────────────────────────────────
def _no_float(obj):
    return json.loads(obj, parse_float=lambda s: (_ for _ in ()).throw(ValueError("non-integer number")))


def parse_framed(body):
    """A body → (record, envelope). Hibás szerkezet → ValueError('<ok>'). Az üres `sigs` itt MEGENGEDETT
    (a verify 'unsigned'-ként jelzi); minden más a SPEC §5.5 zárt/korlátos alakját követi."""
    try:
        framed = _no_float(body) if isinstance(body, str) else body
    except ValueError as e:
        raise ValueError("not-json: %s" % e)
    if not isinstance(framed, dict) or set(framed) != {"record", "envelope"}:
        raise ValueError("not-framed: exactly {record, envelope} required")
    rec, env = framed["record"], framed["envelope"]
    if not isinstance(rec, dict) or not isinstance(env, dict):
        raise ValueError("not-framed: record and envelope must be objects")
    if set(env) != _ENVELOPE_KEYS:
        raise ValueError("envelope-malformed: members must be exactly %s" % sorted(_ENVELOPE_KEYS))
    if not (isinstance(env["record_id"], str) and _SHA.match(env["record_id"])):
        raise ValueError("envelope-malformed: record_id")
    if not (isinstance(env["config_id"], str) and _SHA.match(env["config_id"])):
        raise ValueError("envelope-malformed: config_id")
    dom = env["domain"]
    if not (isinstance(dom, dict) and set(dom) == _DOMAIN_KEYS and all(isinstance(dom[k], str) and _SLUG.match(dom[k]) for k in dom)):
        raise ValueError("envelope-malformed: domain")
    if not (isinstance(env["domain_hash"], str) and _H64.match(env["domain_hash"])):
        raise ValueError("envelope-malformed: domain_hash")
    ep = env["epoch"]
    if isinstance(ep, bool) or not isinstance(ep, int) or not (0 <= ep <= _SAFE_INT):
        raise ValueError("envelope-malformed: epoch")
    sigs = env["sigs"]
    if not isinstance(sigs, list) or len(sigs) > 2:
        raise ValueError("envelope-malformed: sigs")
    for s in sigs:
        if not (isinstance(s, dict) and set(s) == {"issuer", "sig"} and isinstance(s["issuer"], str)
                and _H64.match(s["issuer"]) and isinstance(s["sig"], str) and _H128.match(s["sig"])):
            raise ValueError("envelope-malformed: sigs entry")
    issuers = [s["issuer"] for s in sigs]
    if issuers != sorted(issuers) or len(set(issuers)) != len(issuers):
        raise ValueError("envelope-malformed: sigs order/duplicate")
    return rec, env


def check_framed_shape(body):
    """A `send` kapuja: hibás keret → ValueError (a busz nem fogadja el)."""
    parse_framed(body)


# ── 2. lépés: ellenőrzés a fogadó oldalon ────────────────────────────────────────────────────────
def signed_message(env, role, org):
    """SPEC §5: DOM_AUTH ‖ record_id(32) ‖ config_id(32) ‖ domain_hash(32) ‖ len(role)‖role ‖ epoch_be8 ‖ len(org)‖org."""
    r, o = role.encode("utf-8"), org.encode("utf-8")
    if len(r) > 255 or len(o) > 255:
        raise ValueError("role/org too long")
    return (DOM_AUTH + bytes.fromhex(env["record_id"][7:]) + bytes.fromhex(env["config_id"][7:])
            + bytes.fromhex(env["domain_hash"]) + bytes([len(r)]) + r
            + int(env["epoch"]).to_bytes(8, "big") + bytes([len(o)]) + o)


def load_admission(path):
    if not path:
        return None
    try:
        with open(path, encoding="utf-8") as f:
            adm = json.load(f)
    except (OSError, ValueError):
        return None
    if not isinstance(adm, dict) or not isinstance(adm.get("admitted"), list):
        return None
    return adm


def _external_validator():
    spec = os.environ.get("AGENT_BUS_SDS_VALIDATOR") or os.environ.get("CAPSULE2_SDS_VALIDATOR")
    if not spec:
        return None
    mod, _, fn = spec.partition(":")
    return getattr(importlib.import_module(mod), fn or "validate")


def verify(body, *, sender, admission=None, registry_pubkey=None):
    """Egy sds-envelope busz-sor osztályozása → (status, ok). status: 'valid'|'invalid'|'unsigned'|'unverifiable'."""
    try:
        rec, env = parse_framed(body)
    except ValueError as e:
        return "invalid", str(e).split(":")[0]
    try:
        ext = _external_validator()
    except Exception:
        return "unverifiable", "validator-import"
    # Saját a külső validátor eddig EGYEDÜL döntött, és egy env-változóból tetszőleges modul
    # betölthető (`AGENT_BUS_SDS_VALIDATOR=rogue:ok`) — aláírás, admission, minden megkerülhető volt. Mostantól a
    # BEÉPÍTETT ellenőrzés fut ELŐBB, és a külső CSAK SZIGORÍTHAT: a `valid`-ot lerontja, de nem hozhatja létre.
    base_status, base_why = _builtin_verify(rec, env, sender, admission, registry_pubkey)
    if ext is None:
        return base_status, base_why
    try:
        res = ext({"record": rec, "envelope": env},
                  {"sender": sender, "admission": admission, "registry_pubkey": registry_pubkey,
                   "builtin": {"status": base_status, "why": base_why}})
    except Exception:
        return "unverifiable", "validator-error"
    ext_status, ext_why = ((res, "") if isinstance(res, str) else (res[0], res[1] if len(res) > 1 else ""))
    if base_status != "valid":
        return base_status, base_why                       # a külső nem írhatja felül a beépített elutasítást
    if ext_status != "valid":
        return ext_status, ext_why or "external"
    return "valid", ""


def _builtin_verify(rec, env, sender, admission, registry_pubkey):
    """A beépített, minimális ellenőrzés (szűk JCS-profil). -> (status, ok)"""
    if not env["sigs"]:
        return "unsigned", "no-sigs"
    try:
        if record_id_of(rec) != env["record_id"]:
            return "invalid", "record-id-mismatch"            # SPEC §2 újraszámolva
    except ValueError:
        return "invalid", "record-not-canonicalizable"
    if rec.get("record_id") != env["record_id"]:
        return "invalid", "record-id-binding"                 # SPEC §5.5 RECORD_ID_BINDING_MISMATCH
    if hashlib.sha256(jcs(env["domain"])).hexdigest() != env["domain_hash"]:
        return "invalid", "domain-hash-mismatch"              # SPEC §5.5 fogadó-oldalon újraszámolva
    if admission is None:
        return "unverifiable", "no-admission"                 # role/org nélkül az aláírt üzenet nem építhető fel
    # Saját az OPCIONÁLIS `config_id` csendben kihagyta a kötést -> egy másik config-kontextusba
    # átültetett boríték is átment (cross-config replay). A hiányzó kötés harmadik állapot, nem zöld.
    if admission.get("config_id") is None:
        return "unverifiable", "no-config-binding"
    if admission["config_id"] != env["config_id"]:
        return "invalid", "config-mismatch"
    if admission.get("domain_hash") is not None and admission["domain_hash"] != env["domain_hash"]:
        return "invalid", "domain-hash-mismatch"
    by_issuer = {a.get("issuer"): a for a in admission["admitted"] if isinstance(a, dict)}
    mine = [a for a in admission["admitted"] if isinstance(a, dict) and a.get("sender") == sender]
    if not mine:
        return "invalid", "not-admitted"                      # 3. lépés: a busz-feladó nincs beengedve
    if registry_pubkey is not None and registry_pubkey not in {a.get("issuer") for a in mine}:
        return "invalid", "key-mismatch"                      # 3. lépés: registry-kulcs ≠ beengedett issuer
    if not any(s["issuer"] in {a.get("issuer") for a in mine} for s in env["sigs"]):
        return "invalid", "not-admitted"                      # a feladó saját issuere nem írta alá
    if any(s["issuer"] not in by_issuer for s in env["sigs"]):
        return "invalid", "not-admitted"
    if not HAVE_CRYPTO:
        return "unverifiable", "no-crypto"
    for s in env["sigs"]:
        a = by_issuer[s["issuer"]]
        try:
            # az NFC/NFD kétértelműség két KÜLÖNBÖZŐ aláírt bájtsort ad ugyanarra a látszólagos role/org-ra.
            # A JCS szándékosan nem normalizál, ezért az admission-mezőket normalizáljuk EGYSZER, itt.
            msg = signed_message(env, unicodedata.normalize("NFC", str(a.get("role", ""))),
                                 unicodedata.normalize("NFC", str(a.get("org", ""))))
            _ed.Ed25519PublicKey.from_public_bytes(bytes.fromhex(s["issuer"])).verify(bytes.fromhex(s["sig"]), msg)
        except Exception:
            return "invalid", "bad-signature"
    return "valid", ""


def label(status, why):
    return status if not why or status in ("valid", "unsigned") else "%s(%s)" % (status, why)
