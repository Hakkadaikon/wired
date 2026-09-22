[Docs](../README.md) › [Performance](./) › Monitoring

# moqt_chat wired_server — 5-hour resource monitoring

A continuous resource sample of the `moqt_chat` example's `wired_server`
container (`examples/moqt_chat/docker-compose.yml`, `network_mode: host`)
while 2-4 real users held live WebTransport sessions open. This is a
capacity/health baseline for a single-process, single-core-bound server —
not a throughput benchmark (see [Comparison](comparison.md) for that).

## Method

- Sampled every 10 minutes for 5 hours (30 samples), each sample averaging
  CPU/network deltas over a 3-second window.
- CPU: `/proc/<pid>/stat` utime+stime delta, normalized to percent of one
  core (this server is intentionally single-process/single-thread — see
  `docker-compose.yml`'s own comment on why `--workers`/`--cores` must not
  be passed to this example).
- Memory: `VmRSS` from `/proc/<pid>/status`.
- Network: `/sys/class/net/eth0/statistics/{rx,tx}_bytes` delta. This counts
  ALL traffic on the host's primary interface, not just this container's
  (the container uses `network_mode: host`, so there is no per-container
  interface to isolate) — treat the throughput numbers as an upper bound
  that also includes any other traffic the host happened to carry during
  each 3-second window.
- Raw data: [`perf-monitor.csv`](perf-monitor.csv) (30 rows, one per
  sample).

## Result (30 samples, 2026-09-22 01:42–06:15 JST)

| Metric | Min | Median | Mean | Max |
|---|---|---|---|---|
| CPU (% of 1 core) | 4.00 | 7.67 | 7.80 | 12.00 |
| Memory (VmRSS, MiB) | 20.85 | 20.85 | 20.85 | 20.85 |
| Receive throughput (KB/s) | 35.2 | 57.4 | 68.0 | 187.7 |
| Send throughput (KB/s) | 448.4 | 673.1 | 812.5 | 1474.6 |

- Memory stayed pixel-perfect flat across all 30 samples (20.85 MiB) —
  no sign of a leak over the 5-hour window.
- CPU stayed in a narrow single-digit-to-low-double-digit band (4–12% of
  one core) throughout, tracking connection/share activity rather than
  climbing over time.
- Container status was `running` for every sample; no crash or restart
  during the window.
- Send throughput bursts above receive (expected: the hub fans a shared
  live feed and screen-share/voice traffic out to every connected peer,
  so outbound scales with peer count while inbound is roughly one
  uploader's worth).

## Test machine

The host running this container (ConoHa VPS, KVM guest), from `lscpu`:

| | |
|---|---|
| CPU model | Intel(R) Xeon(R) Gold 6230 @ 2.10GHz |
| vCPUs | 4 (presented as 4×1-core sockets, not one 4-core socket — typical cloud vCPU shape, not a physical 4-socket server) |
| Architecture | x86_64, 46-bit physical / 48-bit virtual addressing |
| Hypervisor | KVM (full virtualization) |
| L1d / L1i cache | 128 KiB each (4 instances) |
| L2 cache | 16 MiB (4 instances) |
| L3 cache | 64 MiB (4 instances) |
| NUMA nodes | 1 |
| Notable ISA extensions | AVX-512 (F/DQ/CD/BW/VL/VNNI), AES-NI, RDRAND/RDSEED |

CPU vulnerability mitigations are the standard set for a 2026-patched Xeon
KVM guest (Meltdown/L1TF/Spectre v1&2/Retbleed mitigated; MDS/MMIO-stale-
data/TSX-async-abort report degraded "no microcode visible to guest"
status, which reflects the hypervisor host, not `wired`) — full
`lscpu` output on request, omitted here as not relevant to the numbers
above.
