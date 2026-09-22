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

`lscpu` on the host running this container (ConoHa VPS, KVM guest):

```
$ lscpu
Architecture:                x86_64
  CPU op-mode(s):            32-bit, 64-bit
  Address sizes:             46 bits physical, 48 bits virtual
  Byte Order:                Little Endian
CPU(s):                      4
  On-line CPU(s) list:       0-3
Vendor ID:                   GenuineIntel
  Model name:                Intel(R) Xeon(R) Gold 6230 CPU @ 2.10GHz
    CPU family:              6
    Model:                   85
    Thread(s) per core:      1
    Core(s) per socket:      1
    Socket(s):               4
    Stepping:                7
    BogoMIPS:                4190.15
    Flags:                   fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca
                             cmov pat pse36 clflush mmx fxsr sse sse2 ss syscall nx
                             pdpe1gb rdtscp lm constant_tsc arch_perfmon rep_good nopl
                             xtopology cpuid tsc_known_freq pni pclmulqdq ssse3 fma
                             cx16 pcid sse4_1 sse4_2 x2apic movbe popcnt tsc_deadline_timer
                             aes xsave avx f16c rdrand hypervisor lahf_lm abm
                             3dnowprefetch cpuid_fault pti ssbd ibrs ibpb stibp
                             fsgsbase tsc_adjust bmi1 hle avx2 smep bmi2 erms invpcid
                             rtm mpx avx512f avx512dq rdseed adx smap clflushopt clwb
                             avx512cd avx512bw avx512vl xsaveopt xsavec xgetbv1 xsaves
                             arat umip pku ospke avx512_vnni
Virtualization features:
  Hypervisor vendor:         KVM
  Virtualization type:       full
Caches (sum of all):
  L1d:                       128 KiB (4 instances)
  L1i:                       128 KiB (4 instances)
  L2:                        16 MiB (4 instances)
  L3:                        64 MiB (4 instances)
NUMA:
  NUMA node(s):              1
  NUMA node0 CPU(s):         0-3
Vulnerabilities:
  Gather data sampling:      Unknown: Dependent on hypervisor status
  Indirect target selection: Mitigation; Aligned branch/return thunks
  Itlb multihit:             KVM: Mitigation: VMX unsupported
  L1tf:                      Mitigation; PTE Inversion
  Mds:                       Vulnerable: Clear CPU buffers attempted, no microcode; SMT Host state unknown
  Meltdown:                  Mitigation; PTI
  Mmio stale data:           Vulnerable: Clear CPU buffers attempted, no microcode; SMT Host state unknown
  Reg file data sampling:    Not affected
  Retbleed:                  Mitigation; IBRS
  Spec rstack overflow:      Not affected
  Spec store bypass:         Mitigation; Speculative Store Bypass disabled via prctl
  Spectre v1:                Mitigation; usercopy/swapgs barriers and __user pointer sanitization
  Spectre v2:                Mitigation; IBRS; IBPB conditional; STIBP disabled; RSB filling; PBRSB-eIBRS Not affected; BHI SW loop, KVM SW loop
  Srbds:                     Not affected
  Tsa:                       Not affected
  Tsx async abort:           Vulnerable: Clear CPU buffers attempted, no microcode; SMT Host state unknown
  Vmscape:                   Not affected
```

Notable: this is a KVM guest with 4 vCPUs presented as 4 separate sockets
(1 core/thread each) rather than a single 4-core socket — a common shape
for cloud VM vCPU allocation, not a 4-socket physical server. Several
mitigations report degraded/unknown status "dependent on hypervisor" or
"no microcode" (MDS, MMIO stale data, TSX async abort) — typical for a VM
where the host's microcode/hypervisor mitigations aren't fully visible to
the guest; this reflects the hosting environment, not anything `wired`
controls.
