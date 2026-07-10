# AF_XDP-driven HTTP/3 server sample

`wired_server.c` is the same demo application as `examples/word_list`
(message log: `POST` appends and echoes, `GET` returns the whole log) but
driven over **AF_XDP** instead of a plain UDP socket: packets are polled
straight out of a shared UMEM ring (RX/TX/Fill/Completion), with zero
per-packet `recvfrom`/`sendto` syscalls on the receive side, instead of the
regular UDP-socket path the other samples use. See
`tasks/xdp-driver-plan.md` for the driver's internal design.

It is libc-free, x86_64-linux only, and runs on direct syscalls with its own
`_start` (a static, freestanding binary) — see `examples/word_list/README.md`
for the shared application behavior and TLS/handshake details this sample
does not repeat.

## Prerequisites

- **root**, to open a raw `AF_XDP` socket and load a BPF program.
- **Linux kernel 5.9 or later** (`BPF_LINK_CREATE` for XDP programs).
- A network interface to bind to — a `veth` pair in its own network
  namespace is the easiest way to test without touching a real NIC.

## Build

```sh
cd examples/word_list_xdp
just build
```

This is not yet wired into the SDK's own `scripts/gen_ninja.sh` build graph,
so `just build` here compiles every `src/**/*.c` straight from source with
one direct `clang` invocation (see the `justfile`), rather than linking
against a prebuilt `build/libwired.a`.

## CLI flags

| flag | required | default | meaning |
|---|---|---|---|
| `--ifindex N` | yes | — | network interface index to bind to |
| `--queue N` | no | `0` | RX queue index to bind |
| `--ip a.b.c.d` | yes | — | our IPv4 address (dotted-quad) |
| `--port N` | no | `4433` | our UDP port |
| `--skb-mode` | no | off | attach the XDP program in generic/SKB mode (`XDP_FLAGS_SKB_MODE`) instead of native mode |
| `--cert PATH` | no | `cert.pem` | certificate chain, same format as `examples/word_list` |
| `--key PATH` | no | `key.pem` | private key, same format as `examples/word_list` |

If `cert.pem`/`key.pem` are absent, the server falls back to its runtime
self-signed identity — see `examples/word_list/README.md`'s "Using an
external CA-issued certificate chain" section for the cert/key requirements
and how to generate a suitable pair.

## veth + netns verification recipe (root required)

`veth` interfaces often do not support **native** XDP, so this recipe uses
`--skb-mode` (generic XDP) from the start.

```sh
sudo ip netns add wiredcli
sudo ip link add veth0 type veth peer name veth1
sudo ip link set veth1 netns wiredcli
sudo ip addr add 10.7.0.1/24 dev veth0 && sudo ip link set veth0 up
sudo ip netns exec wiredcli sh -c 'ip addr add 10.7.0.2/24 dev veth1; ip link set veth1 up; ip link set lo up'
IFIDX=$(ip -o link show veth0 | cut -d: -f1)
sudo ./wired_server --ifindex $IFIDX --queue 0 --ip 10.7.0.1 --port 4433 --skb-mode --cert cert.pem --key key.pem
# from another terminal:
sudo ip netns exec wiredcli curl --http3-only -kv https://10.7.0.1:4433/
```

Stop the server with Ctrl-C (or `SIGTERM`) once done; it prints the
`XDP_STATISTICS` counters (see below) and exits.

### Confirming the path is really going through XDP

- `ip link show veth0` should show an attached program: `xdp` (native) or
  `xdpgeneric` (SKB mode) plus a `prog/id`.
- On exit, the server prints six `XDP_STATISTICS` counters: `rx_dropped`,
  `rx_invalid_descs`, `tx_invalid_descs`, `rx_ring_full`,
  `rx_fill_ring_empty_descs`, `tx_ring_empty_descs`. Their presence (a
  successful `getsockopt(XDP_STATISTICS)`) itself confirms the socket was a
  real AF_XDP socket, not a fallback.
- `/proc/net/udp` still shows the UDP socket bound to the port (it stays
  open for port reservation and to absorb non-QUIC frames the BPF filter
  passes through), but its receive queue (`rx_queue` column) should **not**
  grow under load — traffic for the matched port is redirected to the
  AF_XDP socket by the BPF filter before it ever reaches the UDP socket.

## Cleanup

```sh
sudo ip netns del wiredcli
sudo ip link del veth0
```

## Known limitations

- Only tested against a single-queue interface (`veth` has one RX queue by
  default); a multi-queue NIC needs one `wired_server` instance per queue, or
  `ethtool -L <if> combined 1` to pin it down to one queue first.
- MTU > 1500 / multi-buffer (jumbo frame) packets are not supported.
- `veth`'s `CHECKSUM_PARTIAL` offload means the RX path does not verify the
  IPv4/UDP checksum itself; QUIC's own AEAD authentication is the actual
  integrity guarantee, same as the plain-UDP samples.
