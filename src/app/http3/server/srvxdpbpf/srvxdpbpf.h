#ifndef WIRED_SRVXDPBPF_SRVXDPBPF_H
#define WIRED_SRVXDPBPF_SRVXDPBPF_H

#include "common/platform/sys/syscall.h"

/** @file
 * Shared per-interface BPF objects for the AF_XDP driver: one XSKMAP plus
 * redirect-filter program plus link per ifindex, shared by every per-queue
 * XSK socket (wired_srvxdp). The kernel allows only one XDP link per
 * interface (a second BPF_LINK_CREATE is -EBUSY), so multi-queue servers
 * open this object once per interface and register each queue's XSK socket
 * into its map; the program already redirects by rx_queue_index. */

/** Max XSKMAP entries = max NIC queues servable per interface. */
#define WIRED_SRVXDPBPF_MAP_ENTRIES 64u

/** The three kernel objects backing one interface's redirect filter. */
typedef struct {
  /** XSKMAP fd: rx_queue_index -> XSK socket fd */
  i64 map_fd;
  /** loaded redirect-filter program fd */
  i64 prog_fd;
  /** BPF link fd attaching the program to the interface */
  i64 link_fd;
} wired_srvxdpbpf;

/** Create the XSKMAP (WIRED_SRVXDPBPF_MAP_ENTRIES slots), build and load the
 * redirect-filter program around it (quic_xdpbpf_prog_build, dport == port),
 * and attach it to the interface with a BPF link. On any failure, everything
 * already built is closed in reverse order and every fd is left at -1.
 * @param b            output; all three fds valid on success, -1 on failure
 * @param ifindex      network interface to attach to
 * @param port         UDP destination port the filter redirects
 * @param attach_flags 0 = native XDP, XDP_FLAGS_SKB_MODE(2) = generic/veth
 * @return 0 on success, or a negative errno */
i64 wired_srvxdpbpf_open(
    wired_srvxdpbpf* b, u32 ifindex, u16 port, u32 attach_flags);

/** Point the map's queue_id slot at an XSK socket fd, so frames arriving on
 * that NIC queue are redirected to that socket.
 * @param b        open shared BPF objects for the socket's interface
 * @param queue_id NIC RX queue index (key into the XSKMAP)
 * @param xsk_fd   AF_XDP socket fd bound to that queue
 * @return 0 on success, or a negative errno */
i64 wired_srvxdpbpf_register(wired_srvxdpbpf* b, u32 queue_id, u32 xsk_fd);

/** Close the link, program and map fds in that order (negative fds are
 * skipped) and reset each to -1. Safe to call repeatedly.
 * @param b shared BPF objects to tear down */
void wired_srvxdpbpf_close(wired_srvxdpbpf* b);

#endif
