#!/bin/sh
# AF_XDP smoke test without a NIC: a veth pair, the server's end driven by
# AF_XDP in generic (SKB/copy) mode, a quic-go HTTP/3 client in a network
# namespace on the other end sending one request over IPv4 and one over
# IPv6. Needs root (veth, netns, BPF program load).
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
SRV_IP6=fd00:99::1
CLI_IP6=fd00:99::2
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
# The server end keeps its addresses: the BPF program passes everything but
# UDP to $PORT, so the kernel still answers the client's ARP and IPv6
# neighbour solicitations. nodad: usable at once, no duplicate detection.
ip addr add "$SRV_IP/24" dev "$SRV_IF"
ip addr add "$SRV_IP6/64" dev "$SRV_IF" nodad
ip link set "$SRV_IF" up
ip -n "$NS" addr add "$CLI_IP/24" dev "$CLI_IF"
ip -n "$NS" addr add "$CLI_IP6/64" dev "$CLI_IF" nodad
ip -n "$NS" link set "$CLI_IF" up
ip -n "$NS" link set lo up
# veth offloads the UDP checksum, so the frame reaching XDP carries only a
# partial one and the server's RFC 768 check drops it. Fill it in on send.
ip netns exec "$NS" ethtool -K "$CLI_IF" tx off >/dev/null
# The demo certificate names only localhost and 127.0.0.1, so a request to
# the bare server IPv4 address gets 421. Inside the namespace (ip netns exec
# binds /etc/netns/$NS/hosts over /etc/hosts), localhost is the server. The
# certificate has no IPv6 iPAddress SAN either, so the IPv6 literal request
# is answered 421 (RFC 9110 7.4): any HTTP/3 reply proves the IPv6 path.
mkdir -p "/etc/netns/$NS"
echo "$SRV_IP localhost" >"/etc/netns/$NS/hosts"
IFINDEX="$(cat "/sys/class/net/$SRV_IF/ifindex")"

"$SERVER" --ifindex "$IFINDEX" --port "$PORT" --skb-mode \
  >"$LOG" 2>&1 &
SRV_PID=$!
sleep 1
if ! kill -0 "$SRV_PID" 2>/dev/null; then
  echo "::error::wired_server exited at AF_XDP startup"
  show_log
  exit 1
fi

# Up to three tries; the try that succeeded is printed so the rate stays
# visible in the logs. A server CID without the routing byte used to send
# about one connection in four to an empty XSKMAP slot (srvrun_issue_cid);
# a first-try failure now is a new finding.
request() { # <authority> <body text> <expected status> [expected body]
  printf '%s' "$2" >"$WORK/body"
  try=1
  until ip netns exec "$NS" timeout 20 "$PROBE" h3req "$1" \
    POST / --body-file "$WORK/body" >"$WORK/out" 2>&1; do
    echo "::warning::AF_XDP request to $1 try $try failed"
    cat "$WORK/out"
    if [ "$try" -ge 3 ]; then
      echo "::error::HTTP/3 request to $1 over the AF_XDP path failed"
      show_log
      exit 1
    fi
    try=$((try + 1))
    sleep 1
  done
  echo "AF_XDP request to $1 answered on try $try"
  cat "$WORK/out"
  if ! grep -q "^status $3\$" "$WORK/out" ||
    ! grep -q "^${4:-$2}\$" "$WORK/out"; then
    echo "::error::unexpected reply from $1 over the AF_XDP path"
    show_log
    exit 1
  fi
}

request "localhost:$PORT" 'hello over af_xdp' 200
request "[$SRV_IP6]:$PORT" 'hello over af_xdp ipv6' 421 'Error'

# SIGTERM makes the server print its XDP_STATISTICS before exiting.
kill -TERM "$SRV_PID"
i=0
while kill -0 "$SRV_PID" 2>/dev/null && [ "$i" -lt 150 ]; do
  sleep 0.1
  i=$((i + 1))
done
show_log
echo "AF_XDP smoke: OK"
