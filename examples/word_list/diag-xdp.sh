#!/usr/bin/env bash
# AF_XDP RX-path diagnosis: which layer swallows the packets?
# Run as root on the VPS, from examples/word_list/:
# While it waits, fire ONE curl from the outside machine:
#   docker run --rm ymuski/curl-http3 curl --http3-only --insecure \
#     https://<IP>:4433/ -d hello --max-time 8
set -u

IFINDEX="${IFINDEX:?set IFINDEX=<n> (ip -o link show)}"
IP="${IP:?set IP=<a.b.c.d>}"
PORT="${PORT:-4433}"
WAIT="${WAIT:-20}"
LOG="$(mktemp /tmp/wired-xdp-diag.XXXXXX)"

counter() {
  iptables -L ufw-user-input -n -v -x 2>/dev/null \
    | awk -v p="dpt:$PORT" '$0 ~ p && /udp/ {print $1; exit}'
}

echo "=== counter before ==="
BEFORE="$(counter)"; BEFORE="${BEFORE:-0}"
echo "udp dpt:$PORT accept pkts: $BEFORE"

echo "=== starting wired_server (skb-mode) ==="
./wired_server --ifindex "$IFINDEX" --ip "$IP" --port "$PORT" --skb-mode \
  >"$LOG" 2>&1 &
SRV=$!
sleep 1
if ! kill -0 "$SRV" 2>/dev/null; then
  echo "server died at startup:"; cat "$LOG"; exit 1
fi
ip -o link show | awk -v idx="^$IFINDEX:" '$0 ~ idx {print}'

echo
echo ">>> NOW fire ONE curl from the outside machine. Waiting ${WAIT}s..."
sleep "$WAIT"

echo "=== counter after ==="
AFTER="$(counter)"; AFTER="${AFTER:-0}"
DELTA=$((AFTER - BEFORE))
echo "udp dpt:$PORT accept pkts: $AFTER (delta: $DELTA)"

echo "=== stopping with SIGTERM (stats print on exit) ==="
kill -TERM "$SRV" 2>/dev/null
# drain budget is 25 ticks x 200ms = 5s when a connection stayed up, so give
# the server 15s: exiting at ~5s is itself a signal (a live conn was drained)
TICKS=0
for _ in $(seq 1 150); do
  kill -0 "$SRV" 2>/dev/null || break
  sleep 0.1
  TICKS=$((TICKS + 1))
done
if kill -0 "$SRV" 2>/dev/null; then
  echo "!! server ignored SIGTERM for 15s -> SIGKILL (stats will be missing)"
  kill -KILL "$SRV" 2>/dev/null
else
  echo "server exited on SIGTERM after ~$((TICKS))00ms"
  echo "   (~5000ms = full drain budget = a connection WAS up = RX works)"
fi
wait "$SRV" 2>/dev/null
echo "server exit status: $?"

echo "=== server output ==="
cat "$LOG"

stat() { awk -v k="$1" '$1 == k {print $2; exit}' "$LOG"; }
RXDROP="$(stat rx_dropped)"; RXDROP="${RXDROP:-MISSING}"
FILLEMPTY="$(stat rx_fill_ring_empty_descs)"; FILLEMPTY="${FILLEMPTY:-MISSING}"
RXFULL="$(stat rx_ring_full)"; RXFULL="${RXFULL:-MISSING}"

echo "=== verdict ==="
echo "counter delta=$DELTA rx_dropped=$RXDROP fill_empty=$FILLEMPTY rx_ring_full=$RXFULL"
if [ "$RXDROP" = "MISSING" ]; then
  echo "!! XDP_STATISTICS lines not printed -- server did not exit via SIGTERM path"
elif [ "$DELTA" -gt 0 ]; then
  echo "(A) BPF filter XDP_PASSes the packets -> they reach the kernel UDP stack"
elif [ "${RXDROP}" != "0" ]; then
  echo "(B) redirect happens but the kernel drops at the XSK socket (rx_dropped)"
elif [ "${FILLEMPTY}" != "0" ]; then
  echo "(D-fill) kernel sees an empty fill ring -> ring mmap-offset plumbing broken"
elif [ "${RXFULL}" != "0" ]; then
  echo "(D-consume) RX ring full -> our consumer never drains it"
else
  echo "(OK?) all counters clean, no iptables growth: consistent with the"
  echo "      redirect working (XSK absorbs packets before netfilter) -- but"
  echo "      also with no packets arriving at all. The client's own result"
  echo "      (HTTP response vs timeout) is what distinguishes the two."
fi
rm -f "$LOG"
