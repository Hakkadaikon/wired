#ifndef QUIC_XDPBPF_XDPBPF_H
#define QUIC_XDPBPF_XDPBPF_H

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"

/** @file
 * XDP filter program builder plus the bpf(2) calls needed to run it: create
 * an XSKMAP, load the program, and attach it to an interface with a BPF
 * link. The filter redirects IPv4/UDP frames for one destination port to the
 * XSKMAP, keyed by the QUIC destination CID's leading byte (packed with a
 * worker/core index by quic_ncid_worker_encode, bits=8) when the packet's
 * QUIC header is readable; it falls back to the NIC rx_queue_index when the
 * core-id byte cannot be located (too-short packet, or a zero-length DCID on
 * a long header). Anything that is not IPv4/UDP/dport-match is XDP_PASS, so
 * the kernel keeps handling ARP/ICMP/other traffic.
 *
 * Header-format offsets (RFC 9000 17.2/17.3), all relative to the fixed
 * UDP-payload start at byte 42 (Ethernet 14 + IPv4 IHL=5 20 + UDP 8): a short
 * header's DCID starts right after the 1-byte flags (offset 43); a long
 * header's DCID starts after flags+version(4)+DCID-len(1) (offset 48), and
 * is only present when that DCID-len byte is non-zero. The DCID's length
 * itself never changes where its OWN first byte lands relative to the flags
 * byte in the short-header case (the receiver's fixed CID length is not on
 * the wire at all, RFC 9000 17.3), so short-header routing needs no
 * build-time DCID-length parameter -- only the long-header path reads an
 * explicit length byte, straight off the wire. */

/** Number of u64 instructions quic_xdpbpf_prog_build() emits. */
#define QUIC_XDPBPF_PROG_LEN 40

/** Build the XDP filter into out: eth/IPv4 (IHL=5, non-fragment)/UDP with
 * dport == port is redirected to the XSKMAP map_fd, keyed by the QUIC core-
 * routing byte (falling back to rx_queue_index, see @file); anything else is
 * XDP_PASS. Pure function: a fixed template with the port and map fd patched
 * in. Returns QUIC_XDPBPF_PROG_LEN. */
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
