#!/bin/sh
# Sealed Agent Bus — re-verify the evidence envelope on this machine, offline. Exit 0 only if no chapter failed.
#   ./product/verify_evidence.sh            # all chapters (the coverage floor takes a few minutes)
#   ./product/verify_evidence.sh --quick    # skip the coverage floor
set -eu
DIR="$(cd "$(dirname "$0")" && pwd)"
command -v python3 >/dev/null 2>&1 || { echo "verify: python3 is required" >&2; exit 3; }
exec python3 "$DIR/verify_evidence.py" "$@"
