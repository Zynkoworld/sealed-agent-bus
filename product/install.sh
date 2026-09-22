#!/bin/sh
# Sealed Agent Bus — installer. POSIX sh, no dependencies beyond curl/tar and a sha256 tool.
#
#   curl -fsSL https://zynko.dev/sealed-bus/install.sh | sh -s -- --version 1.5.3
#
# What it does, in this order: download the artifact and its published hash, verify the hash BEFORE unpacking
# anything, unpack into ./sealed-bus-<version>, and run a smoke check. Any failure leaves nothing behind.
#
# Trust note, stated rather than implied: the hash file comes from the same host as the artifact, so on its own it
# proves transfer integrity, not authenticity. Pin the hash you were given out of band:
#
#   ... | sh -s -- --version 1.5.3 --expect-sha256 <64-hex>
#
# No sudo, no service, no account, no telemetry: the installer writes only into --prefix (default: current dir).
set -eu

VERSION=""
BASE_URL="https://zynko.dev/sealed-bus"
PREFIX="."
EXPECT=""

usage() {
    cat <<EOF
usage: install.sh --version X.Y.Z [--prefix DIR] [--url BASE] [--expect-sha256 HEX]
  --version         required, e.g. 1.5.3
  --prefix          where to unpack (default: current directory)
  --url             distribution base URL (default: $BASE_URL)
  --expect-sha256   artifact hash pinned out of band; if given, the downloaded hash file must match it too
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --version) VERSION="${2:-}"; shift 2 ;;
        --prefix) PREFIX="${2:-}"; shift 2 ;;
        --url) BASE_URL="${2:-}"; shift 2 ;;
        --expect-sha256) EXPECT="${2:-}"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "install: unknown option: $1" >&2; usage >&2; exit 2 ;;
    esac
done

[ -n "$VERSION" ] || { echo "install: --version is required (e.g. --version 1.5.3)" >&2; exit 2; }
case "$VERSION" in
    *[!0-9.]*|"") echo "install: --version must look like 1.5.3, got: $VERSION" >&2; exit 2 ;;
esac
if [ -n "$EXPECT" ]; then
    case "$EXPECT" in
        *[!0-9a-f]*|"") echo "install: --expect-sha256 must be 64 lowercase hex characters" >&2; exit 2 ;;
    esac
    [ "${#EXPECT}" -eq 64 ] || { echo "install: --expect-sha256 must be 64 hex characters" >&2; exit 2; }
fi

need() { command -v "$1" >/dev/null 2>&1 || { echo "install: required tool not found: $1" >&2; exit 3; }; }
need curl
need tar
need python3

sha256_of() {
    if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1
    elif command -v shasum >/dev/null 2>&1; then shasum -a 256 "$1" | cut -d' ' -f1
    else python3 -c 'import hashlib,sys;print(hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest())' "$1"
    fi
}

NAME="sealed-bus-$VERSION"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/sealed-bus-install.XXXXXX")"
cleanup() { rm -rf "$TMP"; }
trap cleanup EXIT INT TERM

echo "==> downloading $NAME from $BASE_URL"
curl -fsSL "$BASE_URL/$NAME.tar.gz" -o "$TMP/$NAME.tar.gz" || {
    echo "install: download failed: $BASE_URL/$NAME.tar.gz" >&2; exit 4; }
curl -fsSL "$BASE_URL/$NAME.tar.gz.sha256" -o "$TMP/$NAME.tar.gz.sha256" || {
    echo "install: hash file download failed: $BASE_URL/$NAME.tar.gz.sha256" >&2; exit 4; }

PUBLISHED="$(cut -d' ' -f1 < "$TMP/$NAME.tar.gz.sha256")"
ACTUAL="$(sha256_of "$TMP/$NAME.tar.gz")"
case "$PUBLISHED" in
    *[!0-9a-f]*|"") echo "install: the published hash file is malformed" >&2; exit 5 ;;
esac
if [ "$PUBLISHED" != "$ACTUAL" ]; then
    echo "install: HASH MISMATCH — the archive does not match the published hash. Nothing was unpacked." >&2
    echo "  published: $PUBLISHED" >&2
    echo "  actual:    $ACTUAL" >&2
    exit 5
fi
if [ -n "$EXPECT" ] && [ "$EXPECT" != "$ACTUAL" ]; then
    echo "install: PINNED HASH MISMATCH — the archive differs from the hash you pinned out of band." >&2
    echo "  pinned: $EXPECT" >&2
    echo "  actual: $ACTUAL" >&2
    exit 5
fi
echo "    sha256 ok: $ACTUAL"
[ -n "$EXPECT" ] || echo "    note: the hash came from the same host as the archive — pin it with --expect-sha256 for authenticity"

TARGET="$PREFIX/$NAME"
[ -e "$TARGET" ] && { echo "install: $TARGET already exists — remove it or use --prefix" >&2; exit 6; }
mkdir -p "$PREFIX"
tar xzf "$TMP/$NAME.tar.gz" -C "$TMP" || { echo "install: the archive could not be unpacked" >&2; exit 7; }
[ -d "$TMP/$NAME" ] || { echo "install: the archive does not contain $NAME/" >&2; exit 7; }
mv "$TMP/$NAME" "$TARGET"

echo "==> smoke check"
( cd "$TARGET" && python3 -c 'import agent_bus, bus_notary, bus_enforce; print("    modules load: ok (protocol %s)" % agent_bus.PROTOCOL_VERSION)' ) || {
    echo "install: the unpacked tree does not import — removing it" >&2; rm -rf "$TARGET"; exit 8; }
if ! python3 -c 'import cryptography' >/dev/null 2>&1; then
    echo "    note: python3 'cryptography' is not installed — signatures and the notary need it (pip install cryptography)"
fi

cat <<EOF

installed: $TARGET

next:
  cd $TARGET
  ./product/verify_evidence.sh        # re-verify the evidence envelope on this machine, offline
  python3 agent_bus.py --help         # the bus itself
EOF
