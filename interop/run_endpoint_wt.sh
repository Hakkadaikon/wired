#!/bin/sh
# quic-interop-runner WebTransport endpoint entrypoint (server role only).
# Contract: quic-interop-runner webtransport.md — the runner mounts /www
# (files to serve), /downloads (files to save), /certs (cert.pem + priv.key),
# /logs (QLOGDIR target) and sets ROLE / TESTCASE / PROTOCOLS / REQUESTS /
# SSLKEYLOGFILE. Exit 127 declares an unsupported role or test case.
set -e

if [ "$ROLE" != "server" ]; then
  echo "wired is a server-only endpoint (ROLE=$ROLE unsupported)" >&2
  exit 127
fi

case "$TESTCASE" in
  handshake | transfer | transfer-unidirectional-send | \
      transfer-bidirectional-send | transfer-datagram-send) ;;
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
echo "wired webtransport interop server: testcase=$TESTCASE"

# PROTOCOLS / TESTCASE / REQUESTS reach the binary through the environment.
exec /wired/wired_server \
  --port 443 \
  --cert /certs/cert.pem \
  --key /certs/priv.key \
  $QLOG $KEYLOG
