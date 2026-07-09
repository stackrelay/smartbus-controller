#!/bin/sh
# Run this on the BUILD machine (this Mac) at the start of any smartbus session.
# It answers the only question that matters for safety: am I on the Home LAN,
# i.e. the same network as the NAS + SmartGate? Only there do locally-run
# servers/bridges reach the real house. Office/elsewhere are all "remote".
GATE="192.168.86.166"      # SmartGate — reachable ONLY from the Home LAN
NAS_LOCAL="192.168.86.100" # NAS local IP — Home LAN only
NAS_TS="100.112.109.72"    # NAS Tailscale IP — reachable from anywhere

ips=$(ifconfig 2>/dev/null | awk '/inet /&&$2!="127.0.0.1"{print $2}')
echo "This machine's IPs: $(echo $ips | tr '\n' ' ')"

reach() { ping -c1 -t2 "$1" >/dev/null 2>&1; }

if reach "$GATE" || reach "$NAS_LOCAL"; then
  echo "VERDICT: HOME LAN  — same network as the NAS + SmartGate."
  echo "  * A local server.js hears the real gate; a local homekit-bridge.js advertises into the real Home app."
  echo "  * Do NOT run homekit-bridge.js locally. Keep any local gatewayIp != $GATE. Kill all test procs when done."
elif echo "$ips" | grep -q '192\.168\.86\.'; then
  echo "VERDICT: LIKELY HOME LAN — have a 192.168.86.x IP but gate/NAS not answering. Verify before local testing."
else
  echo "VERDICT: REMOTE (office/elsewhere) — NOT on the Home LAN. Local servers cannot touch the house."
fi

# Tailscale reachability judged by SSH, not ping (Tailscale often drops ICMP).
if ssh -o BatchMode=yes -o ConnectTimeout=6 "Ikem Ugwu@$NAS_TS" true 2>/dev/null; then
  echo "NAS via Tailscale ($NAS_TS): reachable — deploy/inspect over SSH."
else
  echo "NAS via Tailscale ($NAS_TS): NOT reachable over SSH."
fi
