#!/bin/sh
NODE="/volume1/@appstore/Node.js_v18/usr/local/bin/node"
DIR="/volume1/homes/Ikem Ugwu/smartbus-controller"

# Kill the process holding a TCP port (DSM has no lsof/fuser; walk /proc)
# $1 = port in uppercase hex, e.g. 0BBB for 3003, CA72 for 51826
kill_port() {
  INODE=$(awk -v port=":$1" 'NR>1 && $2~port{print $10}' /proc/net/tcp6 2>/dev/null | head -1)
  if [ -z "$INODE" ]; then
    INODE=$(awk -v port=":$1" 'NR>1 && $2~port{print $10}' /proc/net/tcp 2>/dev/null | head -1)
  fi
  if [ -n "$INODE" ]; then
    for p in $(ls /proc | grep "^[0-9]*$"); do
      ls -la /proc/$p/fd 2>/dev/null | grep -q "socket:\[$INODE\]" && kill $p 2>/dev/null && echo "Killed PID $p (port hex $1)"
    done
    sleep 2
  fi
}

kill_port 0BBB   # smartbus server :3003
kill_port CA72   # homekit bridge  :51826

cd "$DIR"
nohup "$NODE" server.js >> "$DIR/server.log" 2>&1 &
echo "Started server PID $!"
sleep 2
if [ -f "$DIR/homekit-bridge.js" ] && [ -f "$DIR/data/homekit.json" ]; then
  # The web app comes first on this 716MB box: run the HomeKit bridge at the
  # lowest CPU priority (nice 19), idle IO class when available, and with a
  # capped V8 heap so it can never balloon and push the server into swap.
  IONICE=""
  command -v ionice >/dev/null 2>&1 && IONICE="ionice -c3"
  nohup $IONICE nice -n 19 "$NODE" --max-old-space-size=48 --max-semi-space-size=2 \
    homekit-bridge.js >> "$DIR/homekit.log" 2>&1 &
  echo "Started homekit bridge PID $! (nice 19, heap-capped)"
fi
