# moqt_chat wired_server — 5-hour resource monitoring

[Docs](../README.md) › [Performance](./) › Monitoring

This page answers one question: does the `moqt_chat` example server stay
healthy when real people use it for hours? We sampled its CPU, memory, and
network use over a 5-hour window while 2-4 real users kept live
[WebTransport sessions](https://hakkadaikon.github.io/wired/guide/en/wt/session/)
open. A long run matters because a short benchmark cannot show slow
problems: a memory leak or CPU use that drifts upward only appears after
hours.

The subject is the `wired_server` container from
`examples/moqt_chat/docker-compose.yml`, which runs with
`network_mode: host` (the container shares the host's network instead of
getting its own virtual interface). This is a capacity/health baseline for
a single-process server bound to one CPU core, not a throughput benchmark
(see [Comparison](comparison.md) for that).

## Method

- Sampled about every 10 minutes during the window (30 samples, first at
  01:42 and last at 06:15 JST; a few samples near the start and end are
  seconds apart). Each sample averages CPU and network deltas over a
  3-second window.
- CPU: the delta of `utime`+`stime` from `/proc/<pid>/stat`, normalized to
  percent of one core. `utime` is time the process spent running its own
  code, `stime` is time the kernel spent working for it (for example
  sending packets). The server is intentionally single-process and
  single-thread; the comment in `docker-compose.yml` explains why
  `--workers`/`--cores` must not be passed to this example.
- Memory: `VmRSS` from `/proc/<pid>/status`. `VmRSS` (resident set size)
  is the amount of the process's memory actually held in RAM right now.
- Network: the delta of `/sys/class/net/eth0/statistics/{rx,tx}_bytes`.
  This counts ALL traffic on the host's primary interface, not just this
  container's. With `network_mode: host` there is no per-container
  interface to isolate, so treat the throughput numbers as an upper bound
  that also includes any other traffic the host carried during each
  3-second window.
- Raw data: [`perf-monitor.csv`](perf-monitor.csv) (30 rows, one per
  sample).

## Result (30 samples, 2026-09-22 01:42–06:15 JST)

| Metric | Min | Median | Mean | Max |
|---|---|---|---|---|
| CPU (% of 1 core) | 4.00 | 7.67 | 7.80 | 12.00 |
| Memory (VmRSS, MiB) | 20.85 | 20.85 | 20.85 | 20.85 |
| Receive throughput (KB/s) | 35.2 | 57.4 | 68.0 | 187.7 |
| Send throughput (KB/s) | 448.4 | 673.1 | 812.5 | 1474.6 |

In this table, KB/s means 1024 bytes per second, and the Median column is
the upper median (the 16th of the 30 sorted values).

- Memory stayed exactly flat across all 30 samples (20.85 MiB): no sign
  of a leak over the 5-hour window.
- CPU stayed in a narrow single-digit-to-low-double-digit band (4–12% of
  one core) throughout, tracking connection/share activity rather than
  climbing over time.
- Container status was `running` for every sample; no crash or restart
  during the window.
- Send throughput is well above receive, as expected. The
  [hub](https://hakkadaikon.github.io/wired/guide/en/moqt/hub/) fans a
  shared live feed and screen-share/voice traffic out to every connected
  peer, so outbound grows with the number of peers while inbound is
  roughly one uploader's worth.

## Test machine

The host running this container (ConoHa VPS, KVM guest), from `lscpu`:

| | |
|---|---|
| CPU model | Intel(R) Xeon(R) Gold 6230 @ 2.10GHz |
| vCPUs | 4 (4 sockets × 1 core) |
| Architecture | x86_64, 46-bit physical / 48-bit virtual addressing |
| Hypervisor | KVM (full virtualization) |
| L1d / L1i cache | 128 KiB each (4 instances) |
| L2 cache | 16 MiB (4 instances) |
| L3 cache | 64 MiB (4 instances) |
| NUMA nodes | 1 |
| Notable ISA extensions | AVX-512 (F/DQ/CD/BW/VL/VNNI), AES-NI, RDRAND/RDSEED |

The guest sees its 4 vCPUs as four 1-core sockets rather than one 4-core
socket. This is the typical shape of cloud vCPUs, not a physical 4-socket
server.

CPU vulnerability mitigations are the standard set for a 2026-patched Xeon
KVM guest (Meltdown/L1TF/Spectre v1&2/Retbleed mitigated; MDS/MMIO-stale-
data/TSX-async-abort report degraded "no microcode visible to guest"
status, which reflects the hypervisor host, not `wired`) — full
`lscpu` output on request, omitted here as not relevant to the numbers
above.
