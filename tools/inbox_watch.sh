#!/usr/bin/env bash
# EGYSEGES AgentBus auto-delivery watcher.
# Arm-old a SAJAT sessionodben a Monitor-eszkozzel (persistent):
#   Monitor: bash "$AGENT_BRIDGE_DIR"/tools/inbox_watch.sh <agent>
# -> magatol jelez uj peer-uzenetre (nincs 'busz'/manualis operator-poke). Egyseges: minden agent ugyanez.
# A self-delivery elve: a bus magatol ebreszt, a chatboxot nem terheli.
AGENT="${1:?hasznalat: inbox_watch.sh <agent>}"
# termék-módban a JSON-tükör NEM kikényszerített csatorna → megtagadjuk (rc=3).
# Az env bármely nem-dev értéke, vagy a bus_enforce szerinti product mód (marker a DB mellett / /etc alatt) elég.
_mode="$(printf '%s' "${AGENT_BUS_MODE:-}" | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')"
_here="$(cd "$(dirname "$0")/.." && pwd)"
if { [ -n "$_mode" ] && [ "$_mode" != "dev" ]; } || \
   python3 -c 'import sys; sys.path.insert(0, sys.argv[1]); import bus_enforce as e; sys.exit(0 if e.mode() == "product" else 1)' "$_here" 2>/dev/null; then
  echo "inbox_watch: TERMEK-MOD — a JSON-tukor nem ellenorzott csatorna; hasznald: agent_bus.py recv --agent $AGENT" >&2
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
# KET FORMATUM VAN A BUSZON: topic+note ES subject+body. Mindkettot nezzuk.
sub = d.get('topic') or d.get('subject') or d.get('title') or ''
kind = d.get('kind') or ''
if not sub:
    # vegso tartalek: a torzs elso ertelmes sora -- SOSE '?', mert a nema targy elrejti a surgosseget
    body = d.get('note') or d.get('body') or ''
    sub = next((l.strip() for l in body.splitlines() if l.strip()), '(nincs targy es nincs torzs)')[:110]
    sub = '[targy nelkul] ' + sub
pri = d.get('priority') or ''
tag = ('[%s]' % kind) if kind and kind not in ('report','info') else ''
tag += ('[!%s]' % pri) if pri and str(pri).lower() in ('high','urgent','surgos') else ''
print(frm, '|', (tag + ' ' if tag else '') + sub)
" 2>/dev/null)
      [ -z "$s" ] && s="$b (OLVASHATATLAN JSON -- nezd meg kezzel)"
      echo "BUS-MSG: $s"
    fi
  done
  sleep 12
done
