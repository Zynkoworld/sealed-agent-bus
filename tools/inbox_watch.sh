#!/usr/bin/env bash
# UNIFIED AgentBus auto-delivery watcher.
# Arm it in YOUR OWN session with the Monitor tool (persistent):
#   Monitor: bash "$AGENT_BRIDGE_DIR"/tools/inbox_watch.sh <agent>
# -> signals by itself on a new peer message (no 'bus'/manual operator poke). Unified: every agent uses the same one.
# The self-delivery principle: the bus wakes by itself, it does not load the chatbox.
AGENT="${1:?usage: inbox_watch.sh <agent>}"
# in product mode the JSON mirror is NOT an enforced channel → we refuse (rc=3).
# Any non-dev value of the env, or product mode per bus_enforce (a marker next to the DB / under /etc) is enough.
_mode="$(printf '%s' "${AGENT_BUS_MODE:-}" | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')"
_here="$(cd "$(dirname "$0")/.." && pwd)"
if { [ -n "$_mode" ] && [ "$_mode" != "dev" ]; } || \
   python3 -c 'import sys; sys.path.insert(0, sys.argv[1]); import bus_enforce as e; sys.exit(0 if e.mode() == "product" else 1)' "$_here" 2>/dev/null; then
  echo "inbox_watch: PRODUCT MODE — the JSON mirror is not a checked channel; use: agent_bus.py recv --agent $AGENT" >&2
  exit 3
fi
DIR="${AGENT_BRIDGE_DIR:-$HOME/.agentbus}/inbox/$AGENT"
declare -A seen
for f in "$DIR"/*.json; do [ -e "$f" ] && seen["$(basename "$f")"]=1; done
while true; do
  for f in "$DIR"/*.json; do
    [ -e "$f" ] || continue
    b="$(basename "$f")"
    if [ -z "${seen[$b]}" ]; then
      seen["$b"]=1
      s=$(python3 -c "
import json,sys
d=json.load(open('$f'))
frm = d.get('from') or d.get('sender') or '?'
# TWO FORMATS ARE ON THE BUS: topic+note AND subject+body. We look at both.
sub = d.get('topic') or d.get('subject') or d.get('title') or ''
kind = d.get('kind') or ''
if not sub:
    # last resort: the first meaningful line of the body -- NEVER '?', because a silent subject hides the urgency
    body = d.get('note') or d.get('body') or ''
    sub = next((l.strip() for l in body.splitlines() if l.strip()), '(no subject and no body)')[:110]
    sub = '[no subject] ' + sub
pri = d.get('priority') or ''
tag = ('[%s]' % kind) if kind and kind not in ('report','info') else ''
tag += ('[!%s]' % pri) if pri and str(pri).lower() in ('high','urgent','surgos') else ''
print(frm, '|', (tag + ' ' if tag else '') + sub)
" 2>/dev/null)
      [ -z "$s" ] && s="$b (UNREADABLE JSON -- check it by hand)"
      echo "BUS-MSG: $s"
    fi
  done
  sleep 12
done
