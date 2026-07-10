#!/usr/bin/env bash
# Manual root-only interop check for the AF_XDP driver: builds a veth pair +
# netns, starts wired_server bound to it via AF_XDP, curls it over HTTP/3, and
# tears every bit of the network setup back down afterwards (even on failure).
# Companion to the "veth + netns verification recipe" in README.md -- same
# recipe, scripted with cleanup guaranteed by a trap.
#
# Usage: sudo ./test-veth.sh
#
# Requires: root, Linux >= 5.9, clang, curl built with HTTP/3 support, openssl.
# ponytail: single-shot manual script, no flags/config -- add if this needs to
# run in CI or with different addressing later.
set -euo pipefail

NETNS=wiredcli-test
VETH_HOST=vethxdp0
VETH_NS=vethxdp1
HOST_IP=10.7.9.1
NS_IP=10.7.9.2
PORT=4433
WORKDIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVER_PID=""

log() { printf '\n=== %s ===\n' "$1"; }

cleanup() {
  log "cleanup"
  if [ -n "$SERVER_PID" ] && kill -0 "$SERVER_PID" 2>/dev/null; then
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
  ip netns exec "$NETNS" true 2>/dev/null && ip netns del "$NETNS" 2>/dev/null || true
  ip link show "$VETH_HOST" >/dev/null 2>&1 && ip link del "$VETH_HOST" 2>/dev/null || true
  rm -f "$WORKDIR/cert.pem" "$WORKDIR/key.pem"
  echo "cleanup done: veth pair, netns, and generated cert/key all removed."
}
trap cleanup EXIT

if [ "$(id -u)" -ne 0 ]; then
  echo "must run as root (AF_XDP socket + BPF prog load need it)" >&2
  exit 1
fi

log "pre-flight"
command -v clang >/dev/null || { echo "clang not found" >&2; exit 1; }
command -v openssl >/dev/null || { echo "openssl not found" >&2; exit 1; }
command -v curl >/dev/null || { echo "curl not found" >&2; exit 1; }
if ! curl --http3-only --version >/dev/null 2>&1; then
  echo "this curl has no HTTP/3 support; interop check will be skipped" >&2
  HAVE_H3=0
else
  HAVE_H3=1
fi

log "build wired_server"
( cd "$WORKDIR" && just build )

log "generate a throwaway self-signed cert"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
  -keyout "$WORKDIR/key.pem" -out "$WORKDIR/cert.pem" -days 1 -nodes \
  -subj "/CN=$HOST_IP"
ls -la "$WORKDIR/cert.pem" "$WORKDIR/key.pem"

log "build veth pair + netns"
ip netns add "$NETNS"
ip link add "$VETH_HOST" type veth peer name "$VETH_NS"
ip link set "$VETH_NS" netns "$NETNS"
ip addr add "$HOST_IP/24" dev "$VETH_HOST"
ip link set "$VETH_HOST" up
ip netns exec "$NETNS" ip addr add "$NS_IP/24" dev "$VETH_NS"
ip netns exec "$NETNS" ip link set "$VETH_NS" up
ip netns exec "$NETNS" ip link set lo up

IFINDEX=$(ip -o link show "$VETH_HOST" | cut -d: -f1 | tr -d ' ')
echo "veth0 ifindex=$IFINDEX, host=$HOST_IP, netns peer=$NS_IP"

log "start wired_server (AF_XDP, generic/skb mode)"
( cd "$WORKDIR" && \
  ./wired_server --ifindex "$IFINDEX" --queue 0 --ip "$HOST_IP" --port "$PORT" \
    --skb-mode --cert cert.pem --key key.pem ) &
SERVER_PID=$!
sleep 1
if ! kill -0 "$SERVER_PID" 2>/dev/null; then
  echo "wired_server exited immediately -- check AF_XDP/BPF support on this kernel" >&2
  exit 1
fi

log "verify the interface shows an attached XDP program"
ip link show "$VETH_HOST" | grep -i xdp || echo "(no xdp line -- attach may have silently fallen back; check server stderr above)"

if [ "$HAVE_H3" -eq 1 ]; then
  log "curl --http3-only through the netns peer"
  if ip netns exec "$NETNS" curl --http3-only -kv "https://$HOST_IP:$PORT/" --max-time 5; then
    echo
    echo "RESULT: HTTP/3 request over AF_XDP succeeded."
  else
    echo
    echo "RESULT: request failed -- see curl -v output above and wired_server's stderr." >&2
  fi
else
  log "skipping curl check (no HTTP/3 support in this curl build)"
fi

log "negative control: kernel UDP socket rx queue should stay idle"
grep -w "$(printf '%04X' "$PORT")" /proc/net/udp || echo "(no matching kernel UDP rx entry -- consistent with traffic going through AF_XDP, not the socket)"

echo
echo "Done. cleanup will now tear down the veth pair, netns, and cert/key."
