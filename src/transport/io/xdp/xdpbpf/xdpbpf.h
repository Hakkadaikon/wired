#ifndef XDPBPF_XDPBPF_H
#define XDPBPF_XDPBPF_H

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"

/** @file
 * XDP filter program builder plus the bpf(2) calls needed to run it: create
 * an XSKMAP, load the program, and attach it to an interface with a BPF
 * link. The filter redirects IPv4/UDP and IPv6/UDP frames (no IPv6
 * extension headers, no IPv4 fragments) for one destination port to the
 * XSKMAP slot of the NIC rx_queue_index. That is the only slot a frame can
 * be delivered to: the kernel refuses an XSK bound to any other queue
 * (xsk_rcv_check, net/xdp/xsk.c) and the frame is dropped. Which worker
 * owns the QUIC connection is decided in user space from the DCID
 * (srvxdp_fwd.c), so a path change (RFC 9000 9) that moves a connection's
 * packets to another queue still reaches it. Anything that is not IPv4- or
 * IPv6-UDP/dport-match is XDP_PASS, so the kernel keeps handling
 * ARP/ICMP/ICMPv6 neighbour discovery/other traffic. */

/** Number of u64 instructions xdpbpf_prog_build() emits. */
#define XDPBPF_PROG_LEN 32

/** Build the XDP filter into out: eth/IPv4 (IHL=5, non-fragment)/UDP or
 * eth/IPv6/UDP with dport == port is redirected to the XSKMAP map_fd under
 * key rx_queue_index; anything else is XDP_PASS. Pure function: a fixed
 * template with the port and map fd patched in. Returns XDPBPF_PROG_LEN. */
usz xdpbpf_prog_build(u64 out[XDPBPF_PROG_LEN], i32 map_fd, u16 port);

/** Create an XSKMAP (key u32 queue index -> value u32 XSK socket fd) with
 * max_entries slots. Returns the map fd, or a negative errno. */
i64 xdpbpf_map_create(u32 max_entries);

/** Set map[key] = xsk_fd in an XSKMAP. Returns 0, or a negative errno. */
i64 xdpbpf_map_set(i64 map_fd, u32 key, u32 xsk_fd);

/** Load cnt XDP instructions (license "Dual MIT/GPL"). If log.n > 0 the
 * verifier log is written into log for diagnosis. Returns the program fd, or
 * a negative errno (e.g. -EACCES when the verifier rejects). */
i64 xdpbpf_prog_load(const u64* insns, u32 cnt, wired_mspan log);

/** Attach a loaded XDP program to ifindex via BPF_LINK_CREATE. flags is 0 for
 * native driver mode or XDP_FLAGS_SKB_MODE (2) for generic mode. Returns the
 * link fd (detaches on close), or a negative errno. */
i64 xdpbpf_link_create(i64 prog_fd, u32 ifindex, u32 flags);

#endif
