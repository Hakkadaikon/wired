# quic-interop-runner endpoint

Minimal scaffolding to run `wired` as a server endpoint under the
[quic-interop-runner](https://github.com/quic-interop/quic-interop-runner).

## Usage (on the runner host)

```sh
just ninja examples/word_list/wired_server
docker build -t wired-interop -f interop/Dockerfile .
# add to the runner's implementations.json:
#   "wired": { "image": "wired-interop", "url": "...", "role": "server" }
python3 run.py -s wired -c quic-go -t handshake,transfer,http3
```

## Supported test cases

`handshake` / `transfer` / `http3` (anything else exits 127 to declare it
unsupported). No client role is provided (server-only SDK, exit 127).

## Limitations

- Response bodies are capped at 16KB per connection slot (larger files 404).
- Retry / address validation is not implemented, so the `retry` test is
  unsupported.
