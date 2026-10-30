#!/usr/bin/env bash
# COTHE LLC — the scan box's OWN Tailscale node for inside-out assessments.
# Separate from any other tailscaled on this box: own binary dir, state, socket, and SOCKS port.
#   Binaries: /opt/cothe-tailscale/{tailscale,tailscaled}   (static release, not the system package)
#   State:    ~/.cothe-tailscale/   SOCKS5: 127.0.0.1:1056 (used by tools/cothe_internal_scan.py)
#
# Usage:
#   tools/cothe_tailscale_box.sh start            # start the daemon (logged out until `up`)
#   COTHE_TS_AUTHKEY=tskey-auth-... tools/cothe_tailscale_box.sh up   # ONE-TIME join of COTHE's tailnet
#   tools/cothe_tailscale_box.sh status           # show peers + approved subnet routes
#   tools/cothe_tailscale_box.sh stop
# Never commit the auth key. Keep it in box secrets as COTHE_TS_AUTHKEY.
set -euo pipefail
BIN=${COTHE_TS_BIN_DIR:-/opt/cothe-tailscale}
DIR=${COTHE_TS_DIR:-$HOME/.cothe-tailscale}
PORT=${COTHE_TS_SOCKS_PORT:-1056}
SOCK="$DIR/tailscaled.sock"
TS="$BIN/tailscale --socket=$SOCK"
mkdir -p "$DIR"; chmod 700 "$DIR"
start() {
  if pgrep -f "tailscaled.*$DIR/state" >/dev/null; then return 0; fi
  nohup "$BIN/tailscaled" --tun=userspace-networking --socks5-server=127.0.0.1:$PORT \
    --state="$DIR/state" --socket="$SOCK" --statedir="$DIR" >>"$DIR/tailscaled.log" 2>&1 &
  for _ in $(seq 20); do [ -S "$SOCK" ] && break; sleep 0.5; done
}
case "${1:-status}" in
  start) start; echo "COTHE tailscaled started (SOCKS 127.0.0.1:$PORT)";;
  up)
    [ -n "${COTHE_TS_AUTHKEY:-}" ] || { echo "Set COTHE_TS_AUTHKEY (from COTHE's Tailscale admin → Settings → Keys)" >&2; exit 1; }
    start
    $TS up --authkey="$COTHE_TS_AUTHKEY" --hostname=cothe-scan-box --accept-routes --advertise-tags=tag:cothe-scanner 2>/dev/null \
      || $TS up --authkey="$COTHE_TS_AUTHKEY" --hostname=cothe-scan-box --accept-routes
    $TS status;;
  status) start; $TS status || true;;
  stop) pkill -f "tailscaled.*$DIR/state" || true; echo stopped;;
  *) sed -n 2,14p "$0"; exit 1;;
esac
