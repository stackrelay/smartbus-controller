#!/bin/sh
NODE="/volume1/@appstore/Node.js_v18/usr/local/bin/node"
DIR="/volume1/homes/Ikem Ugwu/smartbus-controller"

# Find and kill process on port 3003 (hex 0BBB)
INODE=$(awk 'NR>1 && $2~/0BBB/{print $10}' /proc/net/tcp6 2>/dev/null | head -1)
if [ -z "$INODE" ]; then
  INODE=$(awk 'NR>1 && $2~/0BBB/{print $10}' /proc/net/tcp 2>/dev/null | head -1)
fi
if [ -n "$INODE" ]; then
  for p in $(ls /proc | grep "^[0-9]*$"); do
    ls -la /proc/$p/fd 2>/dev/null | grep -q "socket:\[$INODE\]" && kill $p 2>/dev/null && echo "Killed PID $p"
  done
  sleep 2
fi

cd "$DIR"
$NODE server.js >> "$DIR/server.log" 2>&1 &
echo "Started PID $!"
