#!/usr/bin/env python3
"""bus_attach — LARGE CONTENT outside the bus, as a CONTENT-ADDRESSED attachment (v1.2).

Why: AgentBus is COORDINATION (I2), the body size cap is 64 KB, and it DELIBERATELY stays so. Large JSON / files
therefore do not travel on the bus but live in an attachment store; the bus message (kind `attachment`) carries only the DESCRIPTOR:

    {"sha256": "<64 hex>", "size": <bytes>, "media_type": "application/json", "locator": "sha256:<64 hex>"}

An sds-envelope record can also sign the descriptor → the large content stays provable too (the receiver compares the sha256
of the pulled bytes with the descriptor).

Rules:
- **Write-once, no deletion:** the store is `<root>/<hex[:2]>/<hex>`; the same hash a second time = dedupe (it re-checks the existing
  bytes, does not overwrite them). There is no delete API.
- **Check on read:** `get()` compares both the size AND the sha256 → a mismatch = `AttachmentError` (fail-closed).
- **Chunked transport** (SSH / relay): `chunks()` splits into numbered base64 chunks; the receiver's `receive_chunk()`
  appends them in order to a `.partial` file, and puts it into the store ONLY after the last chunk, with a successful hash check.
- **Orphaned half-finished transfer**: the half-finished state is content-addressed, not bound to a sender. A seq-0 chunk
  restarts it if `PARTIAL_STALE_S` (10 minutes) of inactivity has passed since the previous chunk; the orphaned work file
  is moved aside as `.partial.abandoned.<ts>` (not deleted, it counts towards the quota). A seq-0 does not sweep away a live transfer.
stdlib-only."""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import time

ATTACH_KIND = "attachment"
CHUNK_BYTES = 256 * 1024
MAX_ATTACHMENT = int(os.environ.get("AGENT_BUS_ATTACH_MAX", str(512 * 1024 * 1024)))   # 512 MB default ceiling
# The abandoned `.partial` and the hash-failed `.rejected.*` work files NEVER disappear (deliberately, because of the
# no-deletion principle), so a malicious sender could consume the disk without limit through repeated abandoned or hash-failed
# transfers. So a QUOTA on the work files: above it NO NEW transfer starts (fail-closed), the
# one in progress can finish, and nothing is deleted — cleanup is an operator decision (`work_stats()` shows it).
MAX_WORK_BYTES = int(os.environ.get("AGENT_BUS_ATTACH_WORK_QUOTA", str(2 * 1024 * 1024 * 1024)))   # 2 GiB default
# (2026-09-17): after this much inactivity a half-finished transfer counts as ORPHANED, and a seq-0 chunk may restart it
# (the orphaned work file is moved aside, not deleted). Within a round the chunks come seconds apart; 10 minutes of inactivity
# = a broken round, not a slow sender.
# external validation (2026-09-17): setting the env threshold to zero, WITHOUT a lower bound, disabled the protection completely (a LIVE
# transfer was immediately restarted by another party's seq-0). The bus_enforce pattern: env can only NARROW, not widen —
# here: from env the threshold can only GROW above the floor; the floor is 60 s (within a round the chunks come seconds apart).
PARTIAL_STALE_FLOOR_S = 60


def _stale_s():
    try:
        v = int(os.environ.get("AGENT_BUS_ATTACH_PARTIAL_STALE_S", "600"))
    except ValueError:
        v = 600
    return max(PARTIAL_STALE_FLOOR_S, v)


PARTIAL_STALE_S = _stale_s()


def _mtime(path: str) -> float:
    try:
        return os.path.getmtime(path)
    except OSError:
        return 0.0
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_MEDIA = re.compile(r"^[A-Za-z0-9!#$&^_.+-]+/[A-Za-z0-9!#$&^_.+-]+$")
DEFAULT_ROOT = os.environ.get("AGENT_BUS_ATTACH_DIR",
                              os.path.join(os.environ.get("AGENT_BRIDGE_DIR", os.path.expanduser("~/.agentbus")), "attachments"))


class AttachmentError(ValueError):
    """Hash, size or descriptor error (fail-closed)."""


def check_descriptor(desc) -> dict:
    """Check the descriptor's closed structure. -> the descriptor (dict). On error AttachmentError."""
    if isinstance(desc, str):
        try:
            desc = json.loads(desc)
        except ValueError:
            raise AttachmentError("descriptor is not JSON")
    if not isinstance(desc, dict) or set(desc) != {"sha256", "size", "media_type", "locator"}:
        raise AttachmentError("descriptor must have exactly sha256, size, media_type, locator")
    h, size = desc["sha256"], desc["size"]
    if not isinstance(h, str) or not _HEX64.match(h):
        raise AttachmentError("sha256 must be 64 lowercase hex")
    if not isinstance(size, int) or isinstance(size, bool) or not (0 <= size <= MAX_ATTACHMENT):
        raise AttachmentError("size out of range")
    if not isinstance(desc["media_type"], str) or not _MEDIA.match(desc["media_type"]):
        raise AttachmentError("bad media_type")
    if desc["locator"] != "sha256:" + h:
        raise AttachmentError("locator must be sha256:<sha256>")
    return desc


class Store:
    def __init__(self, root: str | None = None):
        self.root = root or DEFAULT_ROOT

    def _path(self, h: str) -> str:
        return os.path.join(self.root, h[:2], h)

    def _verify_file(self, path: str, h: str, size: int | None = None) -> None:
        d, n = hashlib.sha256(), 0
        with open(path, "rb") as f:
            for blk in iter(lambda: f.read(1 << 20), b""):
                d.update(blk)
                n += len(blk)
        if size is not None and n != size:
            raise AttachmentError("size mismatch: descriptor %d, stored %d" % (size, n))
        if d.hexdigest() != h:
            raise AttachmentError("sha256 mismatch")

    def put(self, data: bytes, media_type: str = "application/octet-stream") -> dict:
        """Bytes into the store (write-once, dedupe). -> descriptor."""
        if len(data) > MAX_ATTACHMENT:
            raise AttachmentError("attachment exceeds %d B" % MAX_ATTACHMENT)
        h = hashlib.sha256(data).hexdigest()
        desc = check_descriptor({"sha256": h, "size": len(data), "media_type": media_type, "locator": "sha256:" + h})
        p = self._path(h)
        if os.path.exists(p):                                   # dedupe: the existing one is CHECKED, not overwritten
            self._verify_file(p, h, len(data))
            return desc
        os.makedirs(os.path.dirname(p), exist_ok=True)
        tmp = p + ".tmp.%d.%s" % (os.getpid(), os.urandom(3).hex())
        with open(tmp, "wb") as f:
            f.write(data)
        os.chmod(tmp, 0o444)
        os.replace(tmp, p)
        return desc

    def get(self, desc) -> bytes:
        """The described content, with size and hash checks. Missing or different → AttachmentError."""
        desc = check_descriptor(desc)
        p = self._path(desc["sha256"])
        if not os.path.exists(p):
            raise AttachmentError("attachment not in store")
        self._verify_file(p, desc["sha256"], desc["size"])
        with open(p, "rb") as f:
            return f.read()

    def has(self, desc) -> bool:
        return os.path.exists(self._path(check_descriptor(desc)["sha256"]))

    # ── chunked transport ──────────────────────────────────────────────────
    def chunks(self, desc, chunk_bytes: int = CHUNK_BYTES):
        """The stored content in numbered chunks: {"sha256", "seq", "last", "data"} (data = base64)."""
        data = self.get(desc)
        n = max(1, -(-len(data) // chunk_bytes))
        for i in range(n):
            part = data[i * chunk_bytes:(i + 1) * chunk_bytes]
            yield {"sha256": desc["sha256"], "seq": i, "last": i == n - 1, "data": base64.b64encode(part).decode()}

    def work_stats(self) -> dict:
        """The store's WORK FILES (abandoned `.partial`, orphaned `.partial.abandoned.*`, hash-failed `.rejected.*`)
        — size and count. Deletes nothing: the quota gives a fail-closed gate, cleanup is an operator decision."""
        total, files = 0, []
        for base, _dirs, names in os.walk(self.root):
            for n in names:
                if n.endswith(".done"):
                    continue                                     # the companion file of a finished transfer: not a work file
                if n.endswith(".json") or ".json." in n:
                    continue                                     # the small meta files (live/orphaned/rejected) do not count
                if n.endswith(".partial") or ".rejected." in n or ".abandoned." in n:   # the content files
                    fp = os.path.join(base, n)
                    try:
                        total += os.path.getsize(fp)
                    except OSError:
                        continue
                    files.append(fp)
        return {"bytes": total, "files": len(files), "paths": sorted(files)[:50]}

    def receive_chunk(self, desc, chunk: dict) -> dict | None:
        """Receive one chunk. Bound to order (seq = the number of chunks received so far). After the last chunk the whole
        content goes through a hash+size check, and only then enters the store. -> descriptor (done) or None (more to come)."""
        desc = check_descriptor(desc)
        h = desc["sha256"]
        if not isinstance(chunk, dict) or chunk.get("sha256") != h:
            raise AttachmentError("chunk does not belong to descriptor")
        if self.has(desc):                                      # already present (dedupe) → the chunk is unnecessary
            return desc if chunk.get("last") else None
        p = self._path(h)
        part, meta = p + ".partial", p + ".partial.json"
        os.makedirs(os.path.dirname(p), exist_ok=True)
        try:
            with open(meta, encoding="utf-8") as f:
                expected = json.load(f)["next_seq"]
        except (OSError, ValueError, KeyError):
            expected = 0
        if chunk.get("seq") == 0 and expected > 0:
            # (2026-09-17): the half-finished state is addressed ONLY by the content hash, not bound to a sender, and there
            # was no way back — after a broken round (exactly what the v1.2 header promises to tolerate) EVERY later upload of the same
            # content failed with 'out of order', with no TTL/reset. The way back is the sender's
            # only signal: a seq-0 chunk. But a seq-0 must not sweep away a LIVE transfer in progress (two honest
            # senders of the same content would keep pushing each other) — so only an ORPHANED half-finished state can be restarted:
            # if PARTIAL_STALE_S has passed since the last chunk. No-deletion: the orphaned work file is moved aside
            # (`.partial.abandoned.<ts>`), it counts towards the quota, cleanup is an operator decision.
            idle = time.time() - _mtime(meta)
            if idle < PARTIAL_STALE_S:
                raise AttachmentError("chunk out of order: expected seq %d, got 0 — a transfer of this content is in "
                                      "progress (idle %ds); a seq-0 restart is accepted once it has been idle for %ds"
                                      % (expected, idle, PARTIAL_STALE_S))
            tag = ".abandoned.%d" % int(time.time() * 1000)
            for src in (part, meta):
                if os.path.exists(src):
                    os.replace(src, src + tag)
            expected = 0
        if chunk.get("seq") != expected:
            raise AttachmentError("chunk out of order: expected seq %d, got %r" % (expected, chunk.get("seq")))
        if expected == 0:                                        # a NEW transfer starts: does it still fit into the work-file quota?
            used = self.work_stats()["bytes"]
            if used + int(desc["size"]) > MAX_WORK_BYTES:
                raise AttachmentError("attachment work quota exceeded: %d + %d > %d (cleaning up abandoned/rejected "
                                      "work files is an operator decision)" % (used, desc["size"], MAX_WORK_BYTES))
        try:
            data = base64.b64decode(chunk.get("data", ""), validate=True)
        except (ValueError, TypeError):
            raise AttachmentError("chunk data is not base64")
        cur = os.path.getsize(part) if os.path.exists(part) else 0
        if cur + len(data) > desc["size"]:
            raise AttachmentError("size mismatch: chunks exceed descriptor size")
        with open(part, "ab") as f:
            f.write(data)
        with open(meta, "w", encoding="utf-8") as f:
            json.dump({"next_seq": expected + 1}, f)
        if not chunk.get("last"):
            return None
        try:
            self._verify_file(part, h, desc["size"])
        except AttachmentError:
            os.replace(part, part + ".rejected.%d" % expected)   # kept for inspection, not deleted
            os.replace(meta, meta + ".rejected.%d" % expected)
            raise
        os.chmod(part, 0o444)
        os.replace(part, p)
        os.replace(meta, meta + ".done")
        return desc
