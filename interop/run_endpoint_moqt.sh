#!/bin/sh
# moq-interop-runner relay entrypoint: the runner mounts /certs (cert.pem +
# priv.key) and sets MOQT_PORT (default 4443).
exec /wired/wired_server \
  --port "${MOQT_PORT:-4443}" \
  --cert /certs/cert.pem \
  --key /certs/priv.key
