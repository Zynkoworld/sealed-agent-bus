"""AgentBus security-invariant regression tests (az egyik kar, bus-hardening owner).

Pins the hardening the audit verified SOLID — so it stays enforced: `_safe_name` injectivity + path-safety
(the mirror-injection defense), `verify_sender` anti-spoof classification (A2 Ed25519), and `recv`
deterministic no-dup delivery. Behaviour-only, no change to the bus.
"""
import os
import tempfile

import agent_bus as ab


# ── _safe_name: injective + path-safe (a hostile recipient/sender/topic name can't collide or traverse) ──

def test_safe_name_is_injective_over_sanitized_inputs():
    # two different raw names that naively sanitize to the same 'a-b' must NOT collide (hash suffix, B1)
    assert ab._safe_name("a/b") != ab._safe_name("a-b")
    assert ab._safe_name("a:b") != ab._safe_name("a.b")


def test_safe_name_is_path_safe():
    for hostile in ("../etc", "..", ".", "", "a/../../b", "\x00evil"):
        s = ab._safe_name(hostile)
        assert "/" not in s and s not in ("", ".", "..") and "\x00" not in s


def test_safe_name_unicode_homoglyph_gets_hash_suffix():
    # a non-ASCII name is truncated to ASCII + a hash suffix, so two distinct unicode names can't collide
    a, b = ab._safe_name("café"), ab._safe_name("cafe")
    assert a != b and "~" in a and all(ord(c) < 128 for c in a)


# ── verify_sender: A2 anti-spoof classification ──────────────────────────────────────────────────

def _keypair():
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.hazmat.primitives import serialization
    priv = ed25519.Ed25519PrivateKey.generate()
    pub = priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return priv, pub.hex()


def test_verify_sender_signed_forged_unsigned():
    if not ab._A2_HAVE:
        return
    with tempfile.TemporaryDirectory() as keys:
        priv, pub_hex = _keypair()
        with open(os.path.join(keys, "alice.pub"), "w") as fh:
            fh.write(pub_hex)
        seed = priv.private_bytes_raw().hex()
        msg = {"v": 2, "sender": "alice", "recipient": "bob", "topic": "t", "kind": "msg",
               "in_reply_to": None, "body": "hi", "ts": 123}
        rec = ab._a2_sign(bytes.fromhex(seed), dict(msg))
        signed = {**msg, "sig": rec["sig"], "pubkey": rec["pubkey"]}
        assert ab.verify_sender(signed, keys_dir=keys) == "signed"
        # unsigned under a PINNED name (alice has a registry key) → its own class, not the nameless back-compat
        # verdict
        assert ab.verify_sender({**msg}, keys_dir=keys) == "unsigned-pinned"
        # unsigned under a name the registry does NOT know → back-compat, not a forgery
        assert ab.verify_sender({**msg, "sender": "nobody"}, keys_dir=keys) == "unsigned"
        # tampered body under a valid-looking sig → forged
        assert ab.verify_sender({**signed, "body": "EVIL"}, keys_dir=keys) == "forged"
        # a different sender claiming alice's pubkey mismatch → forged
        assert ab.verify_sender({**signed, "sender": "mallory"}, keys_dir=keys) == "forged"


# ── recv: deterministic, no double-delivery ─────────────────────────────────────────────────────

def test_recv_no_double_delivery_and_ordered():
    with tempfile.TemporaryDirectory() as d:
        db = os.path.join(d, "bus.db")
        ab.init(db=db)
        ab.send("alice", "bob", "first", db=db, mirror=False)
        ab.send("alice", "bob", "second", db=db, mirror=False)
        first = ab.recv("bob", mark=True, db=db)
        assert [r["body"] for r in first] == ["first", "second"]        # ordered by id
        assert ab.recv("bob", mark=True, db=db) == []                    # already delivered → none
        ab.send("alice", "bob", "third", db=db, mirror=False)
        assert [r["body"] for r in ab.recv("bob", mark=True, db=db)] == ["third"]   # only the new one


# ── send auto-sign: the sender's guarded default seed (keys/<sender>.ed25519.key) signs automatically ──

def _seed_registry(d, agent):
    """tmp keys dir with a guarded (root, 0600) seed + matching .pub for `agent`; returns (keys_dir, pub_hex)."""
    keys = os.path.join(d, "keys")
    os.makedirs(keys)
    priv, pub_hex = _keypair()
    kp = os.path.join(keys, "%s.ed25519.key" % agent)
    with open(kp, "w") as fh:
        fh.write(priv.private_bytes_raw().hex())
    os.chmod(kp, 0o600)
    with open(os.path.join(keys, "%s.pub" % agent), "w") as fh:
        fh.write(pub_hex)
    return keys, pub_hex


def test_send_auto_signs_with_default_key_and_verifies():
    if not ab._A2_HAVE:
        return
    with tempfile.TemporaryDirectory() as d:
        keys, pub_hex = _seed_registry(d, "alice")
        db = os.path.join(d, "bus.db")
        old = ab.KEYS_DIR
        ab.KEYS_DIR = keys
        try:
            ab.send("alice", "bob", "auto", db=db, mirror=False)     # no sign_key= → auto-resolves the seed
            msg = ab.recv("bob", db=db)[0]
            assert msg["sig"] and msg["pubkey"] == pub_hex
            assert ab.verify_sender(dict(msg), keys_dir=keys) == "signed"
        finally:
            ab.KEYS_DIR = old


def test_send_auto_sign_no_key_stays_unsigned_and_env_opt_out():
    if not ab._A2_HAVE:
        return
    with tempfile.TemporaryDirectory() as d:
        keys, _ = _seed_registry(d, "alice")
        db = os.path.join(d, "bus.db")
        old = ab.KEYS_DIR
        ab.KEYS_DIR = keys
        try:
            ab.send("mallory", "bob", "nokey", db=db, mirror=False)  # no seed for mallory → unchanged unsigned path
            assert ab.recv("bob", db=db)[0]["sig"] is None
            os.environ["AGENT_BUS_AUTO_SIGN"] = "0"                  # opt-out must win even with a seed present
            try:
                ab.send("alice", "bob", "optout", db=db, mirror=False)
            finally:
                del os.environ["AGENT_BUS_AUTO_SIGN"]
            assert ab.recv("bob", db=db)[1]["sig"] is None
        finally:
            ab.KEYS_DIR = old


def test_auto_sign_guard_rejects_lax_seed_perms():
    with tempfile.TemporaryDirectory() as d:
        keys, _ = _seed_registry(d, "alice")
        assert ab._a2_default_sign_key("alice", keys_dir=keys) is not None
        os.chmod(os.path.join(keys, "alice.ed25519.key"), 0o644)     # group/world-readable seed → guard refuses
        assert ab._a2_default_sign_key("alice", keys_dir=keys) is None
        assert ab._a2_default_sign_key("../alice", keys_dir=keys) is None   # traversal-sanitized
        assert ab._a2_default_sign_key("", keys_dir=keys) is None


def test_a2_strict_marker_toggle(tmp_path, monkeypatch):
    """Fleet-wide reversible toggle: .require_sig.on marker enables strict; absence + empty env = OFF."""
    import agent_bus
    marker = tmp_path / ".require_sig.on"
    monkeypatch.setattr(agent_bus, "_REQUIRE_SIG_MARKER", str(marker))
    monkeypatch.delenv("AGENT_BUS_REQUIRE_SIG", raising=False)
    assert agent_bus._a2_strict() is False          # no marker, no env -> OFF (default preserved)
    marker.write_text("")
    assert agent_bus._a2_strict() is True            # marker present -> strict ON
    marker.unlink()
    assert agent_bus._a2_strict() is False           # rm marker -> reversible OFF
    monkeypatch.setenv("AGENT_BUS_REQUIRE_SIG", "1")
    assert agent_bus._a2_strict() is True            # env var still works independently
