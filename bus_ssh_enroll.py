#!/usr/bin/env python3
"""bus_ssh_enroll — a RESTRICTED authorized_keys line for a remote agent's SSH key (v1.2).

The line binds the key to a SINGLE command, and forbids everything else:

    command="<exchange-parancs> <identity>",restrict,no-pty,no-port-forwarding,no-agent-forwarding,no-X11-forwarding,no-user-rc <pubkey>

- `command=` PINS the identity → the remote party cannot impersonate anyone else (bus_ssh_exchange takes it from the argument).
- In OpenSSH `restrict` forbids everything; we ALSO write out the no-* options, so no gap opens on an older sshd either.
- This module ONLY produces the line, and writes it ONLY into the given file (append, 0600, idempotent). It does NOT touch the sshd
  configuration or the system's authorized_keys — which account the line goes to is the operator's decision. stdlib-only."""
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
_FROM_SAFE = re.compile(r'^[A-Za-z0-9_.:*?/,\[\]!-]+$')      # IP/CIDR/host pattern, without quotes and spaces
_MIN_RSA_BITS = 3072                                        # weak RSA cannot get in


def _key_bits_ok(keytype: str, blob_b64: str) -> tuple:
    """(ok, reason) — the key's STRENGTH, not just its shape.

    `ssh-rsa` used to pass with ANY length (even 512 bits), because we only looked at the base64
    SHAPE, not its content. Here we decode it and read the modulus bit length.
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
    """-> an authorized_keys line (without newline). An invalid identity/key/command → ValueError.

    `source`: an optional `from=` pattern (IP/CIDR/host pattern). Without a source limit a
    leaked key can be used from anywhere in the world — `from=` is the CHEAP second wall.
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
    key = "%s %s" % (parts[0], parts[1])                     # the key comment is left out (no quote/option can get in)
    opts = ",".join(RESTRICTIONS)
    if source:
        if not _FROM_SAFE.match(source) or '"' in source:
            raise ValueError("from= pattern contains unsafe characters")
        opts = 'from="%s",%s' % (source, opts)               # from= stands at the START of the options (readability)
    return 'command="%s %s",%s %s' % (exchange_cmd, identity, opts, key)


def write_line(path: str, line: str) -> bool:
    """Append the line to the GIVEN file (0600). A key already present → no duplicate. -> True if it wrote.

    The idempotence was a SILENT DOWNGRADE — if the key was already present in a WEAKER line
    (e.g. without `restrict`, or pinned to another identity), the module said "already present", and the
    restricted line NEVER got in. From now on: same key + same line → no-op; same key + DIFFERENT line
    → ValueError (the operator should see what to replace), and likewise if the existing line lacks
    `restrict` or `command=`.
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
            return False                                     # exactly the same: no-op
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
        sys.stderr.write("bus_ssh_enroll: WARNING — no `from=` source limit in the line: a leaked key "
                         "can be used from anywhere in the world. If you know the partner's outbound address: --from <IP/CIDR>\n")
    if a.out:
        print("written" if write_line(a.out, line) else "already present")
    else:
        print(line)
    return 0


if __name__ == "__main__":
    sys.exit(main())
