[Docs](README.md) › Comparison

# Implementation Comparison

How wired compares to other HTTP/3 / WebTransport / MOQT implementations, in
features (documented against each project's own sources) and in speed
(measured under pinned, equal conditions).

> **Scope disclaimer.** Every number below is a measurement from one specific
> day (2026-08-04) on one specific machine (a 4-vCPU KVM VM, see the
> [environment appendix](#environment)), against pinned versions. It is not a
> claim of general superiority or inferiority of any implementation. Bad
> numbers are published along with good ones; the full per-run record is in
> the [run manifest](#run-manifest).

Legend: `✅` supported · `Partial` supported with a stated limitation ·
`—` not supported / not measured, with the reason in the cell or footnote.

## Feature matrix

Sources: each cell cites the project's own README/source at the pinned
version — wired at commit `ee86062`, quic-go `v0.61.0`, quiche `0.29.3`,
ngtcp2 `v1.25.0` + nghttp3 `v1.18.0`, picoquic master `0dc8ba8`
(VERSION 1.1.51.1; the project tags no releases) [^pins].

| Axis | wired | quic-go | quiche | ngtcp2 (+nghttp3) | picoquic |
|---|---|---|---|---|---|
| Language | C, freestanding [^w-libc] | Go (pure Go) [^qg-readme] | Rust (+ BoringSSL C/C++) [^qc-readme] | C11 (examples C++23) [^ng-readme] | C [^pq-readme] |
| TLS stack | Own built-in TLS 1.3 (no external TLS library) [^w-tls] | Go standard library crypto/TLS [^qg-readme] | BoringSSL [^qc-readme] | Pluggable: GnuTLS, BoringSSL/aws-lc, Picotls, wolfSSL, LibreSSL, OpenSSL ≥ 3.5 [^ng-readme] | picotls (optional MbedTLS) [^pq-readme] |
| libc dependency | None — every `src/**/*.c` compiles `-ffreestanding -nostdlib`; direct syscalls [^w-libc] | None (no cgo), but requires the Go runtime [^qg-nocgo] | Yes (Rust std + linked BoringSSL) [^qc-readme] | Yes (hosted C11) [^ng-readme] | Yes (hosted C) [^pq-readme] |
| Server binary size (see definition [^binsize]) | 344,880 B (static, no libc) [^binsize] | 10,590,915 B (static Go binary incl. runtime) [^binsize] | 6,115,440 B (stripped; BoringSSL static, glibc dynamic) [^binsize] | — (no native build in this comparison [^binsize]) | — (no native build in this comparison [^binsize]) |
| HTTP/3 (RFC 9114) | ✅ server side [^w-h3] | ✅ [^qg-readme] | ✅ (`h3` module) [^qc-h3] | ✅ via nghttp3 [^ng-h3] | ✅ minimal ("h3zero", demo grade) [^pq-readme] |
| QPACK dynamic table (RFC 9204) | Partial — decoder has a live dynamic table; server advertises capacity 0 and its encoder is static-only [^w-qpack] | — (qpack v0.6.0 is static-table only) [^qg-qpack] | — ("TODO: implement dynamic table") [^qc-qpack] | ✅ (nghttp3 "supports dynamic table") [^ng-qpack] | — (static-only, zero-length dynamic dictionary) [^pq-qpack] |
| WebTransport (RFC 9220 + draft-webtrans-http3) | ✅ server side, interop-tested [^w-wt] | Partial — separate companion module webtransport-go [^qg-readme] | Partial — Extended CONNECT only, no WT session layer [^qc-wt] | Partial — nghttp3 ships RFC 9220/9297 prerequisites only [^ng-wt] | ✅ (`picohttp/webtransport.c`) [^pq-wt] |
| QUIC DATAGRAM (RFC 9221) | ✅ [^w-dgram] | ✅ [^qg-readme] | ✅ [^qc-dgram] | ✅ [^ng-readme] | ✅ [^pq-readme] |
| 0-RTT | ✅ interop-proven (`zerortt` PASS vs quic-go) [^w-interop] | ✅ [^qg-0rtt] | ✅ (`enable_early_data`) [^qc-0rtt] | ✅ [^ng-0rtt] | ✅ [^pq-0rtt] |
| Key Update (RFC 9001 §6) | ✅ interop-proven both directions [^w-interop] | ✅ initiates + responds [^qg-ku] | Partial — responds to peer-initiated only, no local-initiate API [^qc-ku] | ✅ (`ngtcp2_conn_initiate_key_update`) [^ng-ku] | ✅ (`picoquic_start_key_rotation`) [^pq-ku] |
| ECN | Partial — implemented + unit-tested; no third-party E2E verdict (peer limitation) [^w-interop] | ✅ on by default [^qg-ecn] | — (sending ECN not supported) [^qc-ecn] | ✅ (validation state machine) [^ng-ecn] | ✅ (ACK_ECN + counters) [^pq-ecn] |
| Connection migration (server-side path validation) | Partial — implemented; E2E unverdictable (tooling/peer limitations) [^w-interop] | ✅ [^qg-mig] | ✅ [^qc-mig] | ✅ [^ng-mig] | ✅ [^pq-mig] |
| QUIC v2 (RFC 9369) | Partial — implemented + unit-proven; no third-party E2E (peer limitation) [^w-interop] | ✅ [^qg-readme] | — (v1 only) [^qc-v2] | ✅ [^ng-readme] | ✅ [^pq-v2] |
| MOQT | ✅ draft-ietf-moq-transport-19, server/relay role over WebTransport; control-plane interop demonstrated with imquic, data-plane relay unverified [^w-moqt] | — [^qg-nomoqt] | — [^qc-nomoqt] | — [^ng-nomoqt] | — (only a `moqt-16` header string in a test) [^pq-nomoqt] |

For MOQT specifically, the third-party landscape (surveyed 2026-08-04):
imquic supports draft versions 16–19; moxygen 14/15/16/18; libquicr and
moqtail 16; aiomoqt 14/16/18(beta); moq-lite is a diverged fork, not
draft-ietf-moq-transport [^moqt-survey].

## Speed: standardized simulated link (goodput)

Method: [quic-interop-runner](https://github.com/quic-interop/quic-interop-runner)
`goodput` measurement (10 MB transfer over the runner's simulated link,
5 repetitions), runner commit `1d6f655` (2026-04-06). The client is pinned to
the same quic-go interop image for every server
(`martenseemann/quic-go-interop@sha256:c90bccb2…`, containing quic-go
`(devel)` build `fbfa1d5`, go1.26.0), so every server faces identical client
behavior and an identical link. All endpoints run as Docker containers —
one execution form across the row.

| Server | Goodput (5 runs) | Server image |
|---|---|---|
| wired | 7318 (± 37) kbps | `wired-interop` built from commit `ee86062` |
| quic-go | 9541 (± 17) kbps | `martenseemann/quic-go-interop@sha256:c90bccb2…` |
| quiche | 9439 (± 3) kbps | `cloudflare/quiche-qns@sha256:63963aba…` [^img-ver] |
| ngtcp2 | 9414 (± 82) kbps [^ngtcp2-warn] | `ghcr.io/ngtcp2/ngtcp2-interop@sha256:eb9e8405…` (revision `6ce75f02`) |
| picoquic | 9335 (± 5) kbps | `privateoctopus/picoquic@sha256:7e4110e3…` [^img-ver] |

wired's lower goodput is consistent with its known throughput constraint
(see the `multiplexing` row in [Interop Results](interop.md): a functional
pass that misses the runner's 60 s completion bar — a throughput gap, not a
correctness gap). An earlier wired run measured 7129 (± 102) kbps while a
release build was compiling on the same host; it was re-measured on a quiet
machine (the 7318 figure) and both runs are disclosed in the
[manifest](#run-manifest).

## Speed: loopback per-request overhead

Method: one pinned load client (a small quic-go v0.61.0 HTTP/3 client, source
in the [appendix](#bench-client-source)) against each server on `127.0.0.1`,
plain loopback (netem unavailable in this environment). All servers run as
native binaries pinned to CPU core 3; the client uses cores 0–1. Same ECDSA
P-256 certificate, same 1 KiB file, each server at its own defaults (recorded
[below](#server-defaults)). Per round: 100 fresh-connection requests ("TTFB"
[^ttfb-def]) plus 10,000 requests over 20 concurrent streams on warmed
connections ("load"). 5 rounds per server [^warmup-note]. A request
unanswered for 10 s counts as a failure and the worker moves on.

| Server (native) | TTFB p50 (ms) | load req/s | load p50 (ms) | load p99 (ms) | failures |
|---|---|---|---|---|---|
| wired `ee86062` | 6.5 ± 0.6 | 2040 ± 1160 [^wired-stall] | 7.0 ± 0.5 | 9.3 ± 1.0 | 4 / 50,500 |
| quic-go v0.61.0 | 2.3 ± 0.1 | 12,159 ± 426 | 1.4 ± 0.0 | 3.8 ± 0.6 | 0 |
| quiche 0.29.3 (`55886df`) | 1.8 ± 0.1 | 20,559 ± 1703 | 0.9 ± 0.0 | 3.2 ± 0.7 | 0 |
| ngtcp2 | — (no native build attempted: multi-stage autotools chain; measured in the goodput lane only) | | | | |
| picoquic | — (no native build attempted: multi-stage cmake chain incl. picotls; measured in the goodput lane only) | | | | |

Client CPU stayed below saturation in every run (max 129% of a 200% two-core
budget), but at the 12k–20k req/s level the client works hard; read
differences between the fastest servers as lower bounds rather than exact
ratios.

## WebTransport and MOQT

**WebTransport (speed):** not measured. The interop runner's WebTransport
suite contains functional test cases only (fixed-size transfers, no
goodput-style measurement), and a custom benchmark would require writing a
per-implementation application layer, which breaks the equal-conditions
premise. Functional WebTransport interop results against webtransport-go are
in [Interop Results](interop.md).

**MOQT (interop):** wired speaks draft-ietf-moq-transport-19; the only other
implementation surveyed that speaks draft-19 is imquic [^moqt-survey]. A live
session between imquic 0.0.2 (`1f4cbf8`, WebTransport, subprotocol `moqt-19`)
and the wired MOQT server demonstrated certificate acceptance, SETUP
negotiation, SUBSCRIBE → SUBSCRIBE_OK, PUBLISH acceptance (11 objects sent)
and clean close — a first control-plane interop against an independent
implementation. Object delivery through the relay to an imquic subscriber
(data plane) did **not** complete and is unverified; 2 of 7 sessions also
ended in a `Protocol Violation` close. No speed comparison is published for
MOQT.

**MOQT (standalone reference, non-comparative):** in wired's own end-to-end
voice-chat harness — where *both* endpoints (server and JS client) are this
project's implementations, so this is not evidence of interoperability or
relative speed — the healthy-run baseline is 0.36% application frame loss
(5041/5059 frames delivered). It is listed here only as a standalone
reference point.

## Environment

- Host: KVM full-virtualization VM, Intel Xeon Gold 6230 @ 2.10 GHz, 4 vCPUs,
  3.8 GiB RAM, Ubuntu 24.04, kernel 6.8.0-110-generic.
- CPU frequency governor: unknown — the VM does not expose cpufreq sysfs.
- `net.core.rmem_max` fixed at 208 KiB (no privilege to raise it); the
  quic-go client logs a receive-buffer warning in every loopback run. Same
  condition for every server.
- `tc`/netem: unavailable (no CAP_NET_ADMIN); the loopback lane therefore
  runs on an unshaped loopback.
- Loopback lane pinning: server on core 3 (`taskset`), client on cores 0–1.
- Version pins per lane: the goodput lane uses the Docker images listed in
  its table (image-internal versions differ from the native pins — quic-go
  image carries `(devel) fbfa1d5` while the native lane pins `v0.61.0`
  [^img-ver]); the loopback lane uses native builds at the commits in its
  table.

### Server defaults (loopback lane) {#server-defaults}

No tuning was applied; each server ran at its defaults. The knobs that most
directly shape these metrics:

| Knob | wired | quic-go | quiche |
|---|---|---|---|
| Congestion control | NewReno (Cubic/BBR present but not default) | Cubic | Cubic |
| `initial_max_data` | 1 MiB | 768 KiB, auto-tuned up to 15 MiB | 10 MB |
| `initial_max_stream_data` | 48 KiB local / 256 KiB remote / 48 KiB uni | 512 KiB, auto-tuned up to 6 MiB | 1 MB |
| `initial_max_streams_bidi` | 100 (re-granted as requests complete) | 100 | 100 |
| UDP GSO | used | used (with fallback) | used (auto-detected) |
| qlog / debug logging | off | off | off |

### Reproduction

Goodput lane: register `wired` in the runner's `implementations_quic.json`
per [interop/README.md](../interop/README.md), then
`python run.py -s <server> -c quic-go -t goodput` at runner commit `1d6f655`.

Loopback lane servers (each behind `taskset -c 3`):

```sh
wired_server --port 14433 --root <docroot> --cert cert.pem --key key.pem
qgserver -addr 127.0.0.1:14434 -root <docroot> -cert cert.pem -key key.pem   # source below
quiche-server --listen 127.0.0.1:14435 --cert cert.pem --key key.pem --root <docroot>
```

Client (`taskset -c 0,1`): `benchclient -mode ttfb -n 100` and
`benchclient -mode load -n 10000 -c 20` against `https://127.0.0.1:<port>/1k.bin`.

### Bench client and server source {#bench-client-source}

The load client and the quic-go static-file server are ~200 and ~20 lines of
Go on quic-go v0.61.0 (`go.mod` pins `github.com/quic-go/quic-go v0.61.0`).
The client measures per-request latency (dial start → 1 KiB response fully
read, handshake included, for TTFB mode [^ttfb-def]), applies a 10 s
per-request timeout, aborts a run after 500 failures, and reports its own CPU
time so client-saturated runs can be invalidated. Raw sources and run logs
live outside this repository; the full command lines and every run's numbers
are published in the manifest below.

## Run manifest {#run-manifest}

Goodput lane (each value = runner's 5-repetition mean ± sd for that run):

| Server | Run | Result |
|---|---|---|
| wired | quiet re-run (published above) | 7318 (± 37) kbps |
| wired | first run, concurrent with a compiler job (disclosed, not published) | 7129 (± 102) kbps |
| quic-go | single run | 9541 (± 17) kbps |
| quiche | single run | 9439 (± 3) kbps |
| ngtcp2 | single run [^ngtcp2-warn] | 9414 (± 82) kbps |
| picoquic | single run | 9335 (± 5) kbps |

Loopback lane, all 30 runs (no runs excluded; the two wired runs containing
stalled requests are the source of the req/s variance [^wired-stall]):

| server | run | mode | n | fails | req/s | p50 ms | p99 ms | client CPU % |
|---|---|---|---|---|---|---|---|---|
| wired | r1 | ttfb | 100 | 0 | 158.9 | 6.01 | 9.00 | 33 |
| wired | r2 | ttfb | 100 | 0 | 159.0 | 6.07 | 7.74 | 33 |
| wired | r3 | ttfb | 100 | 0 | 158.8 | 6.11 | 7.43 | 33 |
| wired | r4 | ttfb | 100 | 0 | 143.5 | 6.84 | 7.92 | 33 |
| wired | r5 | ttfb | 100 | 0 | 129.0 | 7.39 | 10.39 | 34 |
| wired | r1 | load | 10000 | 0 | 3044.6 | 6.58 | 7.71 | 62 |
| wired | r2 | load | 10000 | 1 | 765.4 | 6.60 | 9.55 | 16 |
| wired | r3 | load | 10000 | 0 | 2868.9 | 6.90 | 9.97 | 64 |
| wired | r4 | load | 10000 | 0 | 2736.5 | 7.29 | 9.24 | 64 |
| wired | r5 | load | 10000 | 3 | 785.7 | 7.62 | 10.10 | 20 |
| quic-go | r1 | ttfb | 100 | 0 | 397.2 | 2.27 | 4.29 | 71 |
| quic-go | r2 | ttfb | 100 | 0 | 374.4 | 2.43 | 4.11 | 76 |
| quic-go | r3 | ttfb | 100 | 0 | 406.6 | 2.28 | 3.37 | 74 |
| quic-go | r4 | ttfb | 100 | 0 | 380.9 | 2.38 | 4.15 | 74 |
| quic-go | r5 | ttfb | 100 | 0 | 399.2 | 2.33 | 4.24 | 75 |
| quic-go | r1 | load | 10000 | 0 | 11941.9 | 1.44 | 3.90 | 85 |
| quic-go | r2 | load | 10000 | 0 | 11547.7 | 1.44 | 4.79 | 82 |
| quic-go | r3 | load | 10000 | 0 | 12654.5 | 1.40 | 3.56 | 86 |
| quic-go | r4 | load | 10000 | 0 | 12371.2 | 1.41 | 3.26 | 87 |
| quic-go | r5 | load | 10000 | 0 | 12278.3 | 1.43 | 3.54 | 84 |
| quiche | r1 | ttfb | 100 | 0 | 504.6 | 1.70 | 5.06 | 94 |
| quiche | r2 | ttfb | 100 | 0 | 499.3 | 1.83 | 3.11 | 96 |
| quiche | r3 | ttfb | 100 | 0 | 480.4 | 1.86 | 3.47 | 93 |
| quiche | r4 | ttfb | 100 | 0 | 467.2 | 1.84 | 4.62 | 87 |
| quiche | r5 | ttfb | 100 | 0 | 483.3 | 1.84 | 3.98 | 92 |
| quiche | r1 | load | 10000 | 0 | 22425.6 | 0.81 | 2.33 | 123 |
| quiche | r2 | load | 10000 | 0 | 20859.8 | 0.86 | 2.95 | 129 |
| quiche | r3 | load | 10000 | 0 | 19227.8 | 0.88 | 3.94 | 111 |
| quiche | r4 | load | 10000 | 0 | 18424.4 | 0.92 | 4.03 | 105 |
| quiche | r5 | load | 10000 | 0 | 21859.4 | 0.82 | 2.87 | 121 |

## Footnotes

[^pins]: picoquic tags no releases (only `draft-16-final`, 2018), so master
    `0dc8ba8` (2026-07-30) is the reference. ngtcp2 v1.25.0 and nghttp3
    v1.18.0 released 2026-07-26.
[^binsize]: Size of the server executable actually measured in the loopback
    lane, after `strip`, including each language's runtime and any statically
    linked TLS. Link forms differ (wired fully static without libc; Go static
    with runtime; quiche dynamic against glibc with static BoringSSL), so
    treat cross-column comparison as indicative only. ngtcp2/picoquic were
    not built natively in this comparison, so no comparable number exists.
[^ttfb-def]: "TTFB" here is measured as dial start → the full 1 KiB response
    body read, including the QUIC+TLS handshake — for a 1 KiB body this is
    indistinguishable from first-byte time, but the definition is the
    implemented one.
[^warmup-note]: The control plan called for a warmup round before the counted
    rounds; in practice only the load mode's in-run connection warmup was
    performed and all 5 rounds are published. Identical for every server, so
    the comparison is unaffected.
[^wired-stall]: In 2 of wired's 5 load runs, 4 requests total (of 50,500)
    were never answered and hit the 10 s client timeout; the timeout wait
    inflates those runs' wall time, which is why wired's req/s mean carries a
    large sd. The per-run rows show the bimodality (healthy runs: 2.7–3.0k
    req/s). This is consistent with the non-deterministic stall documented in
    the `multiplexing` interop case.
[^ngtcp2-warn]: The runner logged 5 "At least one QUIC packet could not be
    decrypted" analysis warnings during the ngtcp2 run; the goodput
    measurement itself completed normally.
[^img-ver]: The quiche and picoquic interop images do not expose their
    internal build version (no OCI revision label, no embedded version
    string); they are identified by image digest only. The quic-go image
    embeds `(devel) fbfa1d5` (extracted via `go version -m`).
[^moqt-survey]: Survey of 7 implementations (2026-08-04): imquic
    (<https://github.com/meetecho/imquic>, version enum v16–v19), moxygen
    (Meta), moq-rs/moq-lite (kixelated, diverged fork), libquicr (Cisco),
    moqtail, aiomoqt, mengelbart/moqtransport.
[^w-libc]: `justfile` (`ninja` recipe compiles every `src/**/*.c` with
    `-ffreestanding -nostdlib`); [Syscalls](syscalls.md).
[^w-tls]: [Features › RFC 8446](features/rfc8446.md) — server side of
    TLS 1.3 embedded in QUIC, 104/105 requirements demonstrated.
[^w-h3]: [Features › RFC 9114](features/rfc9114.md) (81/81 demonstrated);
    `http3` interop PASS in [Interop Results](interop.md).
[^w-qpack]: [Features › RFC 9204](features/rfc9204.md) — decoder applies Set
    Dynamic Table Capacity and resolves dynamic/post-Base references; the
    server advertises `SETTINGS_QPACK_MAX_TABLE_CAPACITY 0` and encodes with
    the static table + literals only.
[^w-wt]: [Features › RFC 9220](features/rfc9220.md),
    [draft-webtrans-http3](features/draft-webtrans-http3.md) (68/68);
    WebTransport interop table in [Interop Results](interop.md) (receive
    directions PASS; `*-send` cases under investigation).
[^w-dgram]: [Features › RFC 9221](features/rfc9221.md) (27/27),
    [RFC 9297](features/rfc9297.md) (22/22); `transfer-datagram-receive`
    interop PASS.
[^w-interop]: [Interop Results](interop.md) — `zerortt`, `keyupdate`,
    `chacha20` PASS vs quic-go; `ecn`, `v2`, `connectionmigration` are
    implemented but carry no third-party verdict (peer/tooling limitations,
    detailed there).
[^w-moqt]: `src/app/moqt/` + `examples/moqt_chat` (draft-ietf-moq-transport-19,
    WT subprotocol `moqt-19`, hub/relay role; SETUP/SUBSCRIBE/PUBLISH subset,
    SUBGROUP_HEADER data plane). Interop evidence: 2026-08-04 imquic session
    (see the MOQT section above). MOQT headers are not yet part of the public
    `wired.h` API surface.
[^qg-readme]: <https://github.com/quic-go/quic-go/blob/v0.61.0/README.md>
    (features list: HTTP/3 incl. RFC 9297, RFC 9221, RFC 9369; pure-Go TLS;
    WebTransport via the companion module webtransport-go).
[^qg-nocgo]: Repo-wide grep at v0.61.0: no `import "C"`; pure Go build.
[^qg-qpack]: <https://github.com/quic-go/qpack/blob/v0.6.0/README.md> — "does
    not support the dynamic table"; pinned as qpack v0.6.0 in quic-go
    v0.61.0's go.mod.
[^qg-0rtt]: v0.61.0 `interface.go` (`Allow0RTT`), `client.go`
    (`DialEarly`/`DialAddrEarly`).
[^qg-ku]: v0.61.0 `internal/handshake/updatable_aead.go`
    (`SetKeyUpdateInterval`, initiates and responds).
[^qg-ecn]: v0.61.0 `sys_conn_oob.go` (`QUIC_GO_DISABLE_ECN` opt-out),
    `internal/ackhandler/ecn.go` (RFC 9002 ECN validation, on by default).
[^qg-mig]: v0.61.0 `path_manager.go` (PATH_CHALLENGE, `validated`, max 3
    tracked paths), `connection.go` (`Conn.AddPath`).
[^qg-nomoqt]: Repo-wide grep at v0.61.0: no `moq`/`moqt` hits.
[^qc-readme]: <https://github.com/cloudflare/quiche/blob/0.29.3/README.md>
    (Rust ≥ 1.88, BoringSSL, optional C FFI).
[^qc-h3]: 0.29.3 `quiche/src/h3/mod.rs` (RFC 9114).
[^qc-qpack]: 0.29.3 `quiche/src/h3/qpack/decoder.rs` — "TODO: implement
    dynamic table"; dynamic-table references rejected.
[^qc-wt]: 0.29.3 `quiche/src/h3/mod.rs` (`enable_extended_connect`,
    RFC 9220); no WebTransport session layer.
[^qc-dgram]: 0.29.3 `quiche/src/lib.rs` (`enable_dgram`,
    `max_datagram_frame_size`).
[^qc-0rtt]: 0.29.3 `quiche/src/lib.rs` (`enable_early_data`).
[^qc-ku]: 0.29.3 `quiche/src/lib.rs` — peer-initiated key-update handling
    only; no public API to initiate one.
[^qc-ecn]: 0.29.3 `quiche/src/lib.rs`: `ecn_counts: None, // sending ECN is
    not supported at this time`.
[^qc-mig]: 0.29.3 `quiche/src/path.rs` (validation states),
    `lib.rs` (`on_peer_migrated`, `probe_path`, `migrate`).
[^qc-v2]: 0.29.3 `quiche/src/lib.rs`: `version_is_supported` accepts v1 only.
[^qc-nomoqt]: Repo-wide grep at 0.29.3: no `moq`/`moqt` hits.
[^ng-readme]: <https://github.com/ngtcp2/ngtcp2/blob/v1.25.0/README.rst>
    (C11 core with no external deps; crypto backend list; RFC 9221 / 9287 /
    9368 / 9369 extensions).
[^ng-h3]: <https://github.com/ngtcp2/nghttp3/blob/v1.18.0/README.rst>
    (RFC 9114 + RFC 9204 in C).
[^ng-qpack]: nghttp3 v1.18.0 README: "It supports dynamic table."
[^ng-wt]: nghttp3 v1.18.0 `nghttp3.h`: `enable_connect_protocol` (RFC 9220)
    and `h3_datagram` (RFC 9297) settings only; no WebTransport API.
[^ng-0rtt]: ngtcp2 v1.25.0 README "Resumption and 0-RTT"; accepted 0-RTT
    data auto-retransmitted by the library.
[^ng-ku]: ngtcp2 v1.25.0 `ngtcp2.h`: `ngtcp2_conn_initiate_key_update`.
[^ng-ecn]: ngtcp2 v1.25.0 `ngtcp2.h` ECN codepoints; `ngtcp2_conn.c`
    `NGTCP2_ECN_STATE_*` validation states.
[^ng-mig]: ngtcp2 v1.25.0 `ngtcp2_conn.c`
    (`conn_recv_non_probing_pkt_on_new_path`), `ngtcp2.h`
    (`ngtcp2_conn_initiate_migration`).
[^ng-nomoqt]: Grep over ngtcp2 v1.25.0 + nghttp3 v1.18.0 trees: no MOQT
    hits.
[^pq-readme]: <https://github.com/private-octopus/picoquic/blob/master/README.md>
    (C core; picotls; h3zero minimal HTTP/3; WebTransport draft; RFC 9221 /
    9368 / 9369 / 9287).
[^pq-qpack]: picoquic `picohttp/h3zero.c`: "zero-length dynamic dictionary
    for QPACK" (static-only).
[^pq-wt]: picoquic `picohttp/webtransport.c`, `pico_webtransport.h`.
[^pq-0rtt]: picoquic `picoquic.h`: `picoquic_is_0rtt_available`,
    0-RTT packet/epoch support.
[^pq-ku]: picoquic `picoquic.h`: `picoquic_start_key_rotation`.
[^pq-ecn]: picoquic `picoquic_internal.h`: `picoquic_frame_type_ack_ecn`,
    ECT(0)/ECT(1)/CE counters.
[^pq-mig]: picoquic `picoquic_internal.h` (`challenge_verified`,
    path-challenge frames), `quicctx.c` (`disable_migration` handling).
[^pq-v2]: picoquic `picoquic_internal.h`: `PICOQUIC_V2_VERSION 0x6b3343cf`.
[^pq-nomoqt]: Grep over picoquic master: only `"moqt-16"` as a WT-Protocol
    header example string in `picoquictest/h3zerotest.c`.
