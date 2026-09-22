#!/usr/bin/env python3
"""bus_attach — NAGY TARTALOM a buszon kívül, TARTALOM-CÍMZETT csatolmányként (v1.2).

Miért: az AgentBus KOORDINÁCIÓ (I2), a body felső mérete 64 KB, és ez SZÁNDÉKOSAN marad. A nagy JSON / fájl
ezért nem a buszon utazik, hanem egy csatolmány-tárban él; a busz-üzenet (kind `attachment`) csak a LEÍRÓT viszi:

    {"sha256": "<64 hex>", "size": <bájt>, "media_type": "application/json", "locator": "sha256:<64 hex>"}

A leírót egy sds-envelope rekordja is aláírhatja → a nagy tartalom is bizonyítható marad (a fogadó a lehúzott
bájtok sha256-ját veti össze a leíróval).

Szabályok:
- **Write-once, nincs törlés:** a tár `<root>/<hex[:2]>/<hex>`; ugyanaz a hash másodszor = dedupe (a meglévő
  bájtokat újraellenőrzi, nem írja felül). Törlő API nincs.
- **Olvasáskor ellenőrzés:** `get()` a méretet ÉS a sha256-ot is összeveti → eltérés = `AttachmentError` (fail-closed).
- **Darabolt szállítás** (SSH / relay): `chunks()` sorszámozott, base64 darabokra bont; a fogadó `receive_chunk()`
  sorrendben fűzi egy `.partial` fájlba, és CSAK az utolsó darab után, sikeres hash-ellenőrzéssel teszi a tárba.
- **Elárvult félkész átvitel**: a félkész állapot tartalom-címzett, feladóhoz nem kötött. Egy seq-0 darab
  akkor indítja újra, ha az előző darab óta `PARTIAL_STALE_S` (10 perc) tétlenség telt el; az elárvult munkafájl
  `.partial.abandoned.<ts>` néven félre kerül (nem törlődik, a kvótába beleszámít). Élő átvitelt seq-0 nem söpör el.
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
MAX_ATTACHMENT = int(os.environ.get("AGENT_BUS_ATTACH_MAX", str(512 * 1024 * 1024)))   # 512 MB alap-plafon
# Saját a félbehagyott `.partial` és a hash-hibás `.rejected.*` munkafájlok SOSEM tűnnek el (a
# no-deletion elv miatt szándékosan), így egy rosszindulatú küldő ismételt, félbehagyott vagy hash-hibás átvitellel
# korlátlanul fogyaszthatja a lemezt. Ezért KVÓTA a munkafájlokra: fölötte ÚJ átvitel nem indul (fail-closed), a
# futóban lévő befejezhető, és semmit nem törlünk — a takarítás operátori döntés (`work_stats()` megmutatja).
MAX_WORK_BYTES = int(os.environ.get("AGENT_BUS_ATTACH_WORK_QUOTA", str(2 * 1024 * 1024 * 1024)))   # 2 GiB alap
# (2026-09-17): ennyi tétlenség után egy félkész átvitel ELÁRVULTNAK számít, és egy seq-0 darab újraindíthatja
# (az elárvult munkafájl félre kerül, nem törlődik). Egy körön belül a darabok másodpercekre jönnek; 10 perc tétlenség
# = megszakadt kör, nem lassú feladó.
# külső validáció (2026-09-17): az env-küszöb ALSÓ korlát nélkül nullára állítva a védelmet teljesen kikapcsolta (egy ÉLŐ
# átvitelt egy másik fél seq-0-ja azonnal újraindított). A bus_enforce mintája: az env csak SZŰKÍTHET, nem tágíthat —
# itt: a küszöb env-ből csak NŐHET a padló fölé; a padló 60 s (egy körön belül a darabok másodpercekre jönnek).
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
    """Hash-, méret- vagy leíró-hiba (fail-closed)."""


def check_descriptor(desc) -> dict:
    """A leíró zárt szerkezetének ellenőrzése. -> a leíró (dict). Hibánál AttachmentError."""
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
        """Bájtok a tárba (write-once, dedupe). -> leíró."""
        if len(data) > MAX_ATTACHMENT:
            raise AttachmentError("attachment exceeds %d B" % MAX_ATTACHMENT)
        h = hashlib.sha256(data).hexdigest()
        desc = check_descriptor({"sha256": h, "size": len(data), "media_type": media_type, "locator": "sha256:" + h})
        p = self._path(h)
        if os.path.exists(p):                                   # dedupe: a meglévőt ELLENŐRIZZÜK, nem írjuk felül
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
        """A leírt tartalom, méret- és hash-ellenőrzéssel. Hiányzó vagy eltérő → AttachmentError."""
        desc = check_descriptor(desc)
        p = self._path(desc["sha256"])
        if not os.path.exists(p):
            raise AttachmentError("attachment not in store")
        self._verify_file(p, desc["sha256"], desc["size"])
        with open(p, "rb") as f:
            return f.read()

    def has(self, desc) -> bool:
        return os.path.exists(self._path(check_descriptor(desc)["sha256"]))

    # ── darabolt szállítás ────────────────────────────────────────────────
    def chunks(self, desc, chunk_bytes: int = CHUNK_BYTES):
        """A tárolt tartalom sorszámozott darabokban: {"sha256", "seq", "last", "data"} (data = base64)."""
        data = self.get(desc)
        n = max(1, -(-len(data) // chunk_bytes))
        for i in range(n):
            part = data[i * chunk_bytes:(i + 1) * chunk_bytes]
            yield {"sha256": desc["sha256"], "seq": i, "last": i == n - 1, "data": base64.b64encode(part).decode()}

    def work_stats(self) -> dict:
        """A tár MUNKAFÁJLJAI (félbehagyott `.partial`, elárvult `.partial.abandoned.*`, hash-hibás `.rejected.*`)
        — méret és darabszám. Semmit nem töröl: a kvóta fail-closed kaput ad, a takarítás operátori döntés."""
        total, files = 0, []
        for base, _dirs, names in os.walk(self.root):
            for n in names:
                if n.endswith(".done"):
                    continue                                     # lezárt átvitel kísérő fájlja: nem munkafájl
                if n.endswith(".json") or ".json." in n:
                    continue                                     # a kis meta fájlok (élő/elárvult/elutasított) nem számítanak
                if n.endswith(".partial") or ".rejected." in n or ".abandoned." in n:   # a tartalom-fájlok
                    fp = os.path.join(base, n)
                    try:
                        total += os.path.getsize(fp)
                    except OSError:
                        continue
                    files.append(fp)
        return {"bytes": total, "files": len(files), "paths": sorted(files)[:50]}

    def receive_chunk(self, desc, chunk: dict) -> dict | None:
        """Egy darab fogadása. Sorrendhez kötött (seq = eddig kapott darabok száma). Az utolsó darab után a teljes
        tartalom hash+méret ellenőrzésen megy át, és csak ekkor kerül a tárba. -> leíró (kész) vagy None (még jön)."""
        desc = check_descriptor(desc)
        h = desc["sha256"]
        if not isinstance(chunk, dict) or chunk.get("sha256") != h:
            raise AttachmentError("chunk does not belong to descriptor")
        if self.has(desc):                                      # már megvan (dedupe) → a darab felesleges
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
            # (2026-09-17): a félkész állapotot CSAK a tartalom hash-e címzi, feladóhoz nincs kötve, és nem
            # volt belőle visszaút — egy megszakadt kör (pont az, amit a v1.2 fejléce elviselni ígér) után ugyanannak a
            # tartalomnak MINDEN későbbi feltöltése 'out of order'-rel bukott, TTL/reset nélkül. A visszaút a feladó
            # egyetlen jele: egy seq-0 darab. De egy seq-0 nem söpörhet el egy ÉLŐ, épp haladó átvitelt (két becsületes
            # feladó ugyanarra a tartalomra egymást lökdösné) — ezért csak az ELÁRVULT félkész állapot indítható újra:
            # ha az utolsó darab óta PARTIAL_STALE_S eltelt. No-deletion: az elárvult munkafájl félre kerül
            # (`.partial.abandoned.<ts>`), a kvótába beleszámít, a takarítás operátori döntés.
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
        if expected == 0:                                        # ÚJ átvitel indul: fér-e még a munkafájlok kvótájába?
            used = self.work_stats()["bytes"]
            if used + int(desc["size"]) > MAX_WORK_BYTES:
                raise AttachmentError("attachment work quota exceeded: %d + %d > %d (a félbehagyott/elutasított "
                                      "munkafájlok takarítása operátori döntés)" % (used, desc["size"], MAX_WORK_BYTES))
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
            os.replace(part, part + ".rejected.%d" % expected)   # megőrizzük vizsgálatra, nem töröljük
            os.replace(meta, meta + ".rejected.%d" % expected)
            raise
        os.chmod(part, 0o444)
        os.replace(part, p)
        os.replace(meta, meta + ".done")
        return desc
