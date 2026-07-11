#ifndef QUIC_XDPBPF_XDPBPF_H
#define QUIC_XDPBPF_XDPBPF_H

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"

/** @file
 * XDP filter program builder plus the bpf(2) calls needed to run it: create
 * an XSKMAP, load the program, and attach it to an interface with a BPF
 * link. The filter redirects IPv4/UDP frames for one destination port to the
 * XSKMAP (key = rx_queue_index) and XDP_PASSes everything else, so the
 * kernel keeps handling ARP/ICMP/other traffic. */

/** Number of u64 instructions quic_xdpbpf_prog_build() emits. */
#define QUIC_XDPBPF_PROG_LEN 23

/** Build the XDP filter into out: eth/IPv4 (IHL=5, non-fragment)/UDP with
 * dport == port is redirected to the XSKMAP map_fd (miss falls back to
 * XDP_PASS); anything else is XDP_PASS. Pure function: a fixed template with
 * the port and map fd patched in. Returns QUIC_XDPBPF_PROG_LEN. */
usz quic_xdpbpf_prog_build(u64 out[QUIC_XDPBPF_PROG_LEN], i32 map_fd, u16 port);

/** Create an XSKMAP (key u32 queue index -> value u32 XSK socket fd) with
 * max_entries slots. Returns the map fd, or a negative errno. */
i64 quic_xdpbpf_map_create(u32 max_entries);

/** Set map[key] = xsk_fd in an XSKMAP. Returns 0, or a negative errno. */
i64 quic_xdpbpf_map_set(i64 map_fd, u32 key, u32 xsk_fd);

/** Load cnt XDP instructions (license "Dual MIT/GPL"). If log.n > 0 the
 * verifier log is written into log for diagnosis. Returns the program fd, or
 * a negative errno (e.g. -EACCES when the verifier rejects). */
i64 quic_xdpbpf_prog_load(const u64* insns, u32 cnt, quic_mspan log);

/** Attach a loaded XDP program to ifindex via BPF_LINK_CREATE. flags is 0 for
 * native driver mode or XDP_FLAGS_SKB_MODE (2) for generic mode. Returns the
 * link fd (detaches on close), or a negative errno. */
i64 quic_xdpbpf_link_create(i64 prog_fd, u32 ifindex, u32 flags);

#endif
