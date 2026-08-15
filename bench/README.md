# bench — comparison lanes

Tooling behind [docs/comparison.md](../docs/comparison.md)'s speed and
footprint tables, runnable locally or via the manual GitHub Actions
workflow (`.github/workflows/comparison.yml`, workflow_dispatch → pick
lanes and rounds; results land in the job summary and artifacts. Hosted
runners are shared hardware — treat those numbers as same-day relative
comparisons, not replacements for the pinned-machine numbers in the doc).

- `client/` — Go load client (quic-go v0.61.0): `-mode ttfb` (fresh
  connection per request) and `-mode load` (warmed connection, 20
  concurrent streams), 10 s per-request timeout, self-reported CPU.
- `qgserver/` — ~20-line quic-go static file server (the quic-go row).
- `run-lane.sh <name> <port> <rounds> <server-cmd...>` — pins the server
  to one core (`SERVER_CPU`, default 3) and the client to others
  (`CLIENT_CPUS`, default 0,1), runs the rounds, and emits one speed line
  per run plus raw `/proc` usage counters per load round.
- `sections.sh <bin>...` — Berkeley `size` dump.
- `report.mjs speed|usage|sections <file>` — markdown tables via
  `lib/aggregate.mjs` (pure functions, tested: `node --test bench/test/`).
- `goodput-setup.sh` / `goodput-ci.sh` — pinned quic-interop-runner
  checkout + one goodput row per server (used by the workflow's goodput
  job; also work locally with Docker + tshark).

Local loopback run, condensed:

```sh
ninja examples/word_list/wired_server
(cd bench/client && go build -o benchclient .)
mkdir -p /tmp/docroot && head -c 1024 /dev/urandom > /tmp/docroot/1k.bin
# cert.pem/key.pem: any ECDSA P-256 pair; the client skips verification
BENCH_CLIENT=$PWD/bench/client/benchclient \
  bench/run-lane.sh wired 14433 5 examples/word_list/wired_server \
  --port 14433 --root /tmp/docroot --cert cert.pem --key key.pem \
  | tee lines.txt
node bench/report.mjs speed lines.txt
node bench/report.mjs usage lines.txt
```
