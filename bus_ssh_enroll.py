#!/usr/bin/env python3
"""bus_ssh_enroll — KORLÁTOZOTT authorized_keys-sor egy távoli agent SSH-kulcsához (v1.2).

A sor a kulcsot EGYETLEN parancshoz köti, és minden mást tilt:

    command="<exchange-parancs> <identity>",restrict,no-pty,no-port-forwarding,no-agent-forwarding,no-X11-forwarding,no-user-rc <pubkey>

- A `command=` az identitást PINELI → a távoli fél nem adhatja ki magát másnak (bus_ssh_exchange az argumentumból veszi).
- A `restrict` az OpenSSH-ban mindent tilt; a no-* opciókat IS kiírjuk, hogy régebbi sshd-n se nyíljon rés.
- Ez a modul CSAK a sort állítja elő, és CSAK a megadott fájlba írja (append, 0600, idempotens). Az sshd-konfigurációhoz,
  a rendszer authorized_keys-éhez NEM nyúl — hogy a sor melyik fiókhoz kerül, az operátor döntése. stdlib-only."""
from __future__ import annotations

import argparse
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

RESTRICTIONS = ("restrict", "no-pty", "no-port-forwarding", "no-agent-forwarding", "no-X11-forwarding", "no-user-rc")
_KEYTYPES = ("ssh-ed25519", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521",
             "sk-ssh-ed25519@openssh.com", "sk-ecdsa-sha2-nistp256@openssh.com", "ssh-rsa")
_B64 = re.compile(r"^[A-Za-z0-9+/]+={0,3}$")
_CMD_SAFE = re.compile(r'^[A-Za-z0-9_./ =:@+-]+$')
_FROM_SAFE = re.compile(r'^[A-Za-z0-9_.:*?/,\[\]!-]+$')      # IP/CIDR/hosztminta, idézőjel és szóköz nélkül
_MIN_RSA_BITS = 3072                                        # a gyenge RSA nem kerülhet be


def _key_bits_ok(keytype: str, blob_b64: str) -> tuple:
    """(ok, ok_vagy_ok) — a kulcs ERŐSSÉGE, nem csak az alakja.

    Saját az `ssh-rsa` eddig BÁRMILYEN hosszal átment (akár 512 bit), mert csak a base64
    ALAKJÁT néztük, a tartalmát nem. Itt dekódoljuk és kiolvassuk a modulus bithosszát.
    """
    import base64
    import struct
    try:
        blob = base64.b64decode(blob_b64, validate=True)
    except Exception:
        return False, "public key blob is not valid base64"
    off, fields = 0, []
    while off + 4 <= len(blob) and len(fields) < 4:
        (n,) = struct.unpack(">I", blob[off:off + 4])
        off += 4
        if n > len(blob) - off:
            return False, "public key blob is malformed"
        fields.append(blob[off:off + n])
        off += n
    if not fields or fields[0].decode("utf-8", "replace") != keytype:
        return False, "public key blob type does not match the key type prefix"
    if keytype == "ssh-rsa":
        if len(fields) < 3:
            return False, "RSA public key blob is malformed"
        modulus = fields[2].lstrip(b"\x00")
        bits = len(modulus) * 8
        if bits < _MIN_RSA_BITS:
            return False, "RSA key is %d bits, the minimum is %d (prefer ssh-ed25519)" % (bits, _MIN_RSA_BITS)
    return True, ""


def enroll_line(identity: str, pubkey: str, exchange_cmd: str, source: str | None = None) -> str:
    """-> egy authorized_keys-sor (újsor nélkül). Érvénytelen identitás/kulcs/parancs → ValueError.

    `source`: opcionális `from=` minta (IP/CIDR/hosztminta). Saját forráskorlát nélkül egy
    kiszivárgott kulcs a világ bármely pontjáról használható — a `from=` az OLCSÓ második fal.
    """
    import agent_bus as ab
    if not identity or ab._safe_name(identity) != identity:
        raise ValueError("identity must be a filesystem-safe name [A-Za-z0-9._-]")
    parts = (pubkey or "").strip().split()
    if len(parts) < 2 or parts[0] not in _KEYTYPES or not _B64.match(parts[1]):
        raise ValueError("not a valid OpenSSH public key line")
    if not exchange_cmd or not _CMD_SAFE.match(exchange_cmd) or '"' in exchange_cmd:
        raise ValueError("exchange command contains unsafe characters")
    ok, why = _key_bits_ok(parts[0], parts[1])
    if not ok:
        raise ValueError(why)
    key = "%s %s" % (parts[0], parts[1])                     # a kulcs-komment kimarad (nem kerülhet bele idézőjel/opció)
    opts = ",".join(RESTRICTIONS)
    if source:
        if not _FROM_SAFE.match(source) or '"' in source:
            raise ValueError("from= pattern contains unsafe characters")
        opts = 'from="%s",%s' % (source, opts)               # a from= az OPCIÓK ELEJÉN áll (olvashatóság)
    return 'command="%s %s",%s %s' % (exchange_cmd, identity, opts, key)


def write_line(path: str, line: str) -> bool:
    """A sor hozzáfűzése a MEGADOTT fájlhoz (0600). Már bent lévő kulcs → nem duplikál. -> True, ha írt.

    Saját az idempotencia CSENDES DOWNGRADE volt — ha a kulcs már bent volt egy GYENGÉBB
    (pl. `restrict` nélküli, vagy más identitásra pinelt) sorban, a modul „already present"-et mondott, és a
    korlátozott sor SOSEM került be. Mostantól: azonos kulcs + azonos sor → no-op; azonos kulcs + ELTÉRŐ sor
    → ValueError (az operátor lássa, hogy mit kellene cserélnie), és ugyanígy, ha a bent lévő sorból hiányzik
    a `restrict` vagy a `command=`.
    """
    if "\n" in line or "\r" in line:
        raise ValueError("line must be a single line")
    key = " ".join(line.rsplit(" ", 2)[-2:])
    existing = ""
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            existing = f.read()
    for ln in existing.splitlines():
        if not ln.strip() or not ln.endswith(key):
            continue
        if ln.strip() == line.strip():
            return False                                     # pontosan ugyanaz: no-op
        raise ValueError("this key is already in %s with a DIFFERENT line (identity or restrictions differ) — "
                         "replace it deliberately, do not stack a second line:\n  existing: %s\n  wanted:   %s"
                         % (path, ln.strip(), line.strip()))
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    with os.fdopen(fd, "a", encoding="utf-8") as f:
        if existing and not existing.endswith("\n"):
            f.write("\n")
        f.write(line + "\n")
    return True


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="restricted authorized_keys line for a remote bus identity")
    p.add_argument("--identity", required=True)
    p.add_argument("--pubkey-file", required=True)
    p.add_argument("--exchange-cmd", required=True, help='e.g. "/usr/bin/python3 /opt/agent-bus/bus_ssh_exchange.py"')
    p.add_argument("--out", help="append to THIS file only (never touches sshd config); omit to print")
    p.add_argument("--from", dest="source", default=None,
                   help='optional from= source restriction (IP/CIDR/host pattern) — a leaked key is then not '
                        'usable from anywhere')
    a = p.parse_args(argv)
    with open(a.pubkey_file, encoding="utf-8") as f:
        line = enroll_line(a.identity, f.read(), a.exchange_cmd, source=a.source)
    if not a.source:
        sys.stderr.write("bus_ssh_enroll: FIGYELEM — nincs `from=` forráskorlát a sorban: egy kiszivárgott kulcs "
                         "a világ bármely pontjáról használható. Ha ismered a partner kimenő címét: --from <IP/CIDR>\n")
    if a.out:
        print("written" if write_line(a.out, line) else "already present")
    else:
        print(line)
    return 0


if __name__ == "__main__":
    sys.exit(main())
