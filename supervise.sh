#!/bin/sh
# Liveness supervisor for the SmartBus server. Point a DSM Task Scheduler
# task at this (runs every 5 min, or on boot-up). It checks whether the web
# server is actually listening on :3003 and starts it if not — the server's
# own watchdog then brings the HomeKit bridges back within ~2 min.
#
# Detects by port, not by process name: the HomeKit bridge shares this
# working directory, so a cwd/name match would see the bridge and wrongly
# conclude the server is up even when it has died.
NODE="/volume1/@appstore/Node.js_v18/usr/local/bin/node"
DIR="/volume1/homes/Ikem Ugwu/smartbus-controller"

# Is something listening on :3003 (hex 0BBB) locally? field 2 = local_address
if awk '$2 ~ /:0BBB$/ {f=1} END {exit !f}' /proc/net/tcp /proc/net/tcp6 2>/dev/null; then
  exit 0   # server is up — nothing to do
fi

echo "$(date): server not listening on 3003 — restarting" >> "$DIR/server.log"
cd "$DIR"
"$NODE" server.js >> "$DIR/server.log" 2>&1 &
