#!/bin/sh
# Liveness supervisor for the SmartBus server. Point a DSM Task Scheduler
# task at this (every 5 min, and/or on boot-up). Starts the server only if it
# is neither listening NOR already coming up; the server's own watchdog then
# brings the HomeKit bridges back within ~2 min.
NODE="/volume1/@appstore/Node.js_v18/usr/local/bin/node"
DIR="/volume1/homes/Ikem Ugwu/smartbus-controller"

# 1) Already listening on :3003 (hex 0BBB)? Then it's up — done.
if awk '$2 ~ /:0BBB$/ {f=1} END {exit !f}' /proc/net/tcp /proc/net/tcp6 2>/dev/null; then
  exit 0
fi

# 2) A server.js can be mid-startup but not yet bound — Node takes minutes to
#    reach listen() when the box is swap-thrashing. Spawning another here is
#    exactly what pieced together the duplicate bursts. So if ANY node
#    server.js process for this app already exists, leave it to finish.
#    (cwd + exe check can't be fooled by a shell whose text contains "server.js".)
for p in $(ls /proc 2>/dev/null | grep '^[0-9]*$'); do
  [ "$(readlink /proc/$p/cwd 2>/dev/null)" = "$DIR" ] || continue
  case "$(readlink /proc/$p/exe 2>/dev/null)" in */node) ;; *) continue ;; esac
  if tr '\0' ' ' < /proc/$p/cmdline 2>/dev/null | grep -q 'server\.js'; then
    echo "$(date): server.js already starting (pid $p) — not spawning" >> "$DIR/server.log"
    exit 0
  fi
done

# 3) Genuinely down and nothing starting — launch it, detached so it survives
#    this task shell exiting (setsid if present, else nohup).
echo "$(date): server not running — starting" >> "$DIR/server.log"
cd "$DIR"
if command -v setsid >/dev/null 2>&1; then
  setsid "$NODE" server.js >> "$DIR/server.log" 2>&1 &
else
  nohup "$NODE" server.js >> "$DIR/server.log" 2>&1 &
fi
