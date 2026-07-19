#!/bin/sh
# quic-interop-runner endpoint entrypoint (server role only).
# Contract: https://github.com/quic-interop/quic-interop-runner —
# the runner mounts /www (served files), /certs (cert.pem + priv.key),
# /logs (QLOGDIR target), and sets ROLE / TESTCASE / SSLKEYLOGFILE.
# Exit 127 declares an unsupported role or test case.
set -e

if [ "$ROLE" != "server" ]; then
  echo "wired is a server-only endpoint (ROLE=$ROLE unsupported)" >&2
  exit 127
fi

# http3 (ALPN h3) plus the HTTP/0.9 (hq-interop, see hq09.h) cases that need
# no per-testcase server mode: the plain transfers, the loss/corruption/
# latency scenarios (the server just has to survive them), chacha20 (cipher
# negotiated per the client's offer), keyupdate (server follows the
# client-initiated update), amplificationlimit (verifies the server's own
# anti-amplification gate), rebind-port/rebind-addr (the server always
# follows a confirmed connection's peer address), ecn (the server marks
# ECT(0) on send and reports received ECN counts in its 1-RTT ACKs), and the
# two throughput measurements. Still refused: cases needing a dedicated
# server mode that is not wired up yet -- retry, resumption, zerortt, v2,
# connectionmigration, ipv6.
case "$TESTCASE" in
  http3 | handshake | transfer) ;;
  longrtt | multiplexing | chacha20 | keyupdate | multiconnect) ;;
  blackhole | handshakeloss | transferloss) ;;
  handshakecorruption | transfercorruption | amplificationlimit) ;;
  rebind-port | rebind-addr | ecn) ;;
  goodput | crosstraffic) ;;
  *)
    echo "unsupported test case: $TESTCASE" >&2
    exit 127
    ;;
esac

# Simulator routing + UDP checksum-offload disable: the base image's own
# entrypoint runs /setup.sh before serving, and replacing the entrypoint
# means we must run it ourselves or the sim's packets never reach us.
/setup.sh

QLOG=""
[ -n "$QLOGDIR" ] && QLOG="--qlog-file $QLOGDIR/server.sqlog"
KEYLOG=""
[ -n "$SSLKEYLOGFILE" ] && KEYLOG="--keylog-file $SSLKEYLOGFILE"

# The runner health-checks the endpoint before starting the client.
echo "wired interop server: testcase=$TESTCASE"

exec /wired/wired_server \
  --port 443 \
  --root /www \
  --cert /certs/cert.pem \
  --key /certs/priv.key \
  $QLOG $KEYLOG
