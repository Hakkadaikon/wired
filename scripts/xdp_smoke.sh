#!/bin/sh
# AF_XDP smoke test without a NIC: a veth pair, the server's end driven by
# AF_XDP in generic (SKB/copy) mode, a quic-go HTTP/3 client in a network
# namespace on the other end. Needs root (veth, netns, BPF program load).
#
#   sudo scripts/xdp_smoke.sh <wired_server> <probe>
#
# <wired_server>: examples/word_list/wired_server (POST echoes the body).
# <probe>: guide/probe built as a binary.
set -eu

SERVER="$1"
PROBE="$2"
NS=wiredxdp
SRV_IF=wxdp0
CLI_IF=wxdp1
SRV_IP=10.99.0.1
CLI_IP=10.99.0.2
PORT=4433
WORK="$(mktemp -d)"
LOG="$WORK/server.log"
SRV_PID=""

cleanup() {
  if [ -n "$SRV_PID" ] && kill -0 "$SRV_PID" 2>/dev/null; then
    kill -KILL "$SRV_PID" 2>/dev/null || true
  fi
  ip netns del "$NS" 2>/dev/null || true
  ip link del "$SRV_IF" 2>/dev/null || true
  rm -rf "/etc/netns/$NS"
  rm -rf "$WORK"
}
trap cleanup EXIT

show_log() {
  echo "=== server output ==="
  cat "$LOG"
}

ip netns add "$NS"
ip link add "$SRV_IF" type veth peer name "$CLI_IF"
ip link set "$CLI_IF" netns "$NS"
# The server end keeps an address: the BPF program passes everything but
# UDP to $PORT, so the kernel still answers the client's ARP.
ip addr add "$SRV_IP/24" dev "$SRV_IF"
ip link set "$SRV_IF" up
ip -n "$NS" addr add "$CLI_IP/24" dev "$CLI_IF"
ip -n "$NS" link set "$CLI_IF" up
ip -n "$NS" link set lo up
# veth offloads the UDP checksum, so the frame reaching XDP carries only a
# partial one and the server's RFC 768 check drops it. Fill it in on send.
ip netns exec "$NS" ethtool -K "$CLI_IF" tx off >/dev/null
# The demo certificate names only localhost and 127.0.0.1, so a request to
# the bare server IP gets 421. Inside the namespace (ip netns exec binds
# /etc/netns/$NS/hosts over /etc/hosts), localhost is the server.
mkdir -p "/etc/netns/$NS"
echo "$SRV_IP localhost" >"/etc/netns/$NS/hosts"
IFINDEX="$(cat "/sys/class/net/$SRV_IF/ifindex")"

"$SERVER" --ifindex "$IFINDEX" --ip "$SRV_IP" --port "$PORT" --skb-mode \
  >"$LOG" 2>&1 &
SRV_PID=$!
sleep 1
if ! kill -0 "$SRV_PID" 2>/dev/null; then
  echo "::error::wired_server exited at AF_XDP startup"
  show_log
  exit 1
fi

printf 'hello over af_xdp' >"$WORK/body"
if ! ip netns exec "$NS" timeout 20 "$PROBE" h3req "localhost:$PORT" \
  POST / --body-file "$WORK/body" >"$WORK/out" 2>&1; then
  echo "::error::HTTP/3 request over the AF_XDP path failed"
  cat "$WORK/out"
  show_log
  exit 1
fi
cat "$WORK/out"
if ! grep -q '^status 200$' "$WORK/out" ||
  ! grep -q '^hello over af_xdp$' "$WORK/out"; then
  echo "::error::unexpected reply over the AF_XDP path"
  show_log
  exit 1
fi

# SIGTERM makes the server print its XDP_STATISTICS before exiting.
kill -TERM "$SRV_PID"
i=0
while kill -0 "$SRV_PID" 2>/dev/null && [ "$i" -lt 150 ]; do
  sleep 0.1
  i=$((i + 1))
done
show_log
echo "AF_XDP smoke: OK"
