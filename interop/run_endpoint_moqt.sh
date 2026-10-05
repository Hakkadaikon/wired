#!/bin/sh
# moq-interop-runner relay entrypoint: the runner mounts /certs (cert.pem +
# priv.key) and sets MOQT_PORT (default 4443).
#
# One UDP port serves both MoQT transports: ALPN h3 (WebTransport, the
# runner's https:// relay URL) and ALPN moqt-22/moqt-19/moqt-18 (raw QUIC,
# moqt://). The runner registers this same image twice (`wired` and
# `wired-quic`) only because it keys the relay URL on the image name.
#
# MOQT_TRANSPORT (debug, default `both`): `wt` serves WebTransport only
# (--no-raw). `quic` is not supported: h3 cannot be switched off, so a
# raw-QUIC-only run is just a moqt:// client against the default.
case "${MOQT_TRANSPORT:-both}" in
  both | quic) set -- ;;
  wt) set -- --no-raw ;;
  *)
    echo "run_endpoint_moqt.sh: MOQT_TRANSPORT must be both|wt|quic" >&2
    exit 2
    ;;
esac
exec /wired/wired_server \
  --port "${MOQT_PORT:-4443}" \
  --cert /certs/cert.pem \
  --key /certs/priv.key \
  "$@"
