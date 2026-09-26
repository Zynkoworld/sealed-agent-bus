#!/usr/bin/env bash
# In product mode the JSON mirror is NOT an enforced channel → we refuse (rc=3).
# Any non-dev value of the env, or product mode per bus_enforce (a marker next to the DB / under /etc) is enough.
_mode="$(printf '%s' "${AGENT_BUS_MODE:-}" | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')"
_here="$(cd "$(dirname "$0")/.." && pwd)"
if { [ -n "$_mode" ] && [ "$_mode" != "dev" ]; } || \
   python3 -c 'import sys; sys.path.insert(0, sys.argv[1]); import bus_enforce as e; sys.exit(0 if e.mode() == "product" else 1)' "$_here" 2>/dev/null; then
  echo "inbox_watch_filtered: PRODUCT MODE — the JSON mirror is not a checked channel; use: agent_bus.py recv --agent <agent>" >&2
  exit 3
fi
# EXAMPLE: a filtered bus watcher for an agent in a coordinator role.
# The shared tools/inbox_watch.sh wakes on EVERY message — if there are many routine guard alerts, it keeps waking
# day and night and burns tokens.
#
# This variant wakes ONLY for these (stdout = a Monitor event):
#   1) a peer agent's report: from ∈ $WATCH_PEERS AND kind ∉ {alert, riasztas}
#   2) a priority sender: from = $WATCH_PRIORITY_SENDER
#   3) a real emergency alert: a CRITICAL signal in the topic/body (key/leak/disk/OOM/backup failure/quota stop)
# Every other alert does NOT wake, but goes into the digest — nothing is lost, it just does not wake.
# Customize: AGENT=<your agent name>, WATCH_PEERS="a,b,c", WATCH_PRIORITY_SENDER=<sender>.
BRIDGE="${AGENT_BRIDGE_DIR:-$HOME/.agentbus}"
AGENT="${AGENT:-$(basename "$PWD")}"
WATCH_PEERS="${WATCH_PEERS:-}"
WATCH_PRIORITY_SENDER="${WATCH_PRIORITY_SENDER:-}"
DIR="$BRIDGE/inbox/$AGENT"
DIGEST="${WATCH_DIGEST:-$BRIDGE/alert_digest.log}"
declare -A seen
for f in "$DIR"/*.json; do [ -e "$f" ] && seen["$(basename "$f")"]=1; done
while true; do
  for f in "$DIR"/*.json; do
    [ -e "$f" ] || continue
    b="$(basename "$f")"
    [ -n "${seen[$b]}" ] && continue
    seen["$b"]=1
    out=$(python3 - "$f" "$DIGEST" "$WATCH_PEERS" "$WATCH_PRIORITY_SENDER" <<'PY' 2>/dev/null
import json, sys, time, re
f, digest = sys.argv[1], sys.argv[2]
peers = {a.strip().lower() for a in (sys.argv[3] if len(sys.argv) > 3 else "").split(",") if a.strip()}
priority_sender = (sys.argv[4] if len(sys.argv) > 4 else "").strip().lower()
try:
    d = json.load(open(f))
except Exception:
    print("EMIT|BUS-MSG: %s (UNREADABLE JSON)" % f); sys.exit()
frm = (d.get('from') or d.get('sender') or '?').lower()
kind = (d.get('kind') or '').lower()
sub = d.get('topic') or d.get('subject') or d.get('title') or ''
body = d.get('note') or d.get('body') or ''
if not sub:
    sub = '[no subject] ' + next((l.strip() for l in body.splitlines() if l.strip()), '')[:110]
CRIT = re.compile(r'kulcs.?szivar|key.?leak|leak-scan.*talalat|szivarog|disk.?(full|tele)|no space|oom|backup.?(fail|hiba)|kvota.?(stop|80)|quota.?exhaust.*all', re.I)
is_alert = kind in ('alert', 'riasztas') or bool(re.search(r'health-cron|FAIL-LOUD|RED-TEAM|freshness|anti-masking', sub, re.I))  # machine guard messages also count as alerts -> digest
line = "%s | %s%s" % (frm, ('[%s] ' % kind) if kind and kind not in ('report', 'info') else '', sub)
if (priority_sender and frm == priority_sender) or (frm in peers and not is_alert) or CRIT.search(sub + ' ' + body[:400]):
    print("EMIT|BUS-MSG: " + line)
else:
    with open(digest, 'a', encoding='utf-8') as fh:
        fh.write("%s  %s\n" % (time.strftime('%Y-%m-%d %H:%M'), line[:300]))
    print("SKIP|")
PY
)
    case "$out" in EMIT\|*) echo "${out#EMIT|}";; esac
  done
  sleep 12
done
