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

## WebTransport mode

A second image runs the WebTransport test suite
(`run.py --protocol webtransport`, see the runner's `webtransport.md`)
against `examples/webtransport_interop/wired_server`:

```sh
just gen-ninja && ninja examples/webtransport_interop/wired_server
docker build -t wired-interop-wt -f interop/Dockerfile.webtransport .
# add to the runner's implementations_webtransport.json:
#   "wired": { "image": "wired-interop-wt", "url": "...", "role": "server" }
python3 run.py --protocol webtransport -s wired -c webtransport-go -t handshake
```

Supported test cases: `handshake`, `transfer`,
`transfer-unidirectional-send`, `transfer-bidirectional-send`,
`transfer-datagram-send` (anything else, and any non-server role, exits
127). The server reads `PROTOCOLS` / `TESTCASE` / `REQUESTS` from the
environment, serves `GET` requests from `/www/<endpoint>/` and saves
transfer results under `/downloads/<endpoint>/`.

## Limitations

- Response bodies larger than 16KB are served from a shared large-body pool
  (`srvbigbuf`, 2 rows) instead of the fixed per-slot 16KB storage; the
  `http3` test case's 500KB file fits within this and passes. A third
  concurrent large body beyond the pool's row count still falls back to the
  16KB-capped path.
- Retry / address validation is not implemented, so the `retry` test is
  unsupported.
