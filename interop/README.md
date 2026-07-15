# quic-interop-runner endpoint

Minimal scaffolding to run `wired` as a server endpoint under the
[quic-interop-runner](https://github.com/quic-interop/quic-interop-runner).

## Usage (on the runner host)

```sh
just gen-ninja && ninja examples/word_list/wired_server
docker build -t wired-interop -f interop/Dockerfile .
# add to the runner's implementations_quic.json:
#   "wired": { "image": "wired-interop", "url": "...", "role": "server" }
python3 run.py -s wired -c quic-go -t handshake,transfer,http3
```

`tasks/verify/02_interop_runner.sh` automates all of the above (including a
venv for the runner's Python requirements). The runner additionally needs
Docker, docker compose, and Wireshark 4.5+ (`tshark`).

## Supported test cases

`http3` only (anything else exits 127 to declare it unsupported). No client
role is provided (server-only SDK, exit 127).

Every other QUIC test case — including `handshake` and `transfer` —
transfers files over HTTP/0.9 (ALPN `hq-interop`, see the runner's
`quic.md`), which this HTTP/3-only server does not speak.

## Limitations

- Response bodies larger than 16KB are served from a shared large-body pool
  (`srvbigbuf`, 2 rows) instead of the fixed per-slot 16KB storage; the
  `http3` test case's 500KB file fits within this and passes. A third
  concurrent large body beyond the pool's row count still falls back to the
  16KB-capped path.
- Retry / address validation is not implemented, so the `retry` test is
  unsupported.
