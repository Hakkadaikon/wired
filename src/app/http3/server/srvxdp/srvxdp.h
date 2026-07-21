#ifndef WIRED_SRVXDP_SRVXDP_H
#define WIRED_SRVXDP_SRVXDP_H

#include "app/http3/server/srvxdpbpf/srvxdpbpf.h"
#include "common/bytes/span/span.h"
#include "transport/io/socket/io/udp.h"
#include "transport/io/xdp/xdpmac/xdpmac.h"
#include "transport/io/xdp/xsksetup/xsksetup.h"
#include "transport/io/xdp/xskumem/xskumem.h"

/** @file
 * AF_XDP driver integration for the HTTP/3 server: opens one AF_XDP socket
 * plus its BPF redirect filter, and drives the resulting rings with the
 * app-facing quic_mmsg_buf shape. Delegates every actual mechanism to its
 * lower-layer domain (xsksetup for the syscall plumbing, xdpbpf for the
 * filter program, xdpframe for the wire codec, xdpmac for the reflect cache,
 * xskumem for the TX frame pool): this file is only the driving glue
 * between them. */

/** Caller-supplied configuration for one AF_XDP-backed server socket. */
typedef struct {
  u32 ifindex;      /**< network interface index */
  u32 queue_id;     /**< RX queue index to bind */
  u8  ip[4];        /**< our IPv4 address, host-readable octets a.b.c.d */
  u16 port;         /**< our UDP port, host order */
  u16 bind_flags;   /**< passed through to quic_xsk_cfg */
  u32 attach_flags; /**< 0 = native XDP, XDP_FLAGS_SKB_MODE(2) = generic/veth */
} wired_srvxdp_cfg;

/** One open AF_XDP driver instance: the socket/rings, the TX frame pool,
 * the learned peer MAC cache, and — when this instance opened its own BPF
 * redirect filter rather than joining a shared one — those BPF objects. */
typedef struct {
  quic_xsk           xsk;        /**< AF_XDP socket, UMEM and four rings */
  quic_xskumem_alloc txpool;     /**< TX frame pool, UMEM frames 64..127 */
  quic_xdpmac        macs;       /**< peer ip -> mac reflect cache */
  u8                 our_mac[6]; /**< learned from the first RX frame */
  int                have_mac;   /**< 0 until our_mac is learned */
  u32                ip_be;      /**< cfg->ip, network byte order */
  u16                port;       /**< cfg->port, host order */
  /** BPF map/prog/link owned by this instance; fds are -1 when opened
   * against a shared wired_srvxdpbpf (wired_srvxdp_open_shared) */
  wired_srvxdpbpf bpf;
  /** 1 when wired_srvxdp_open built bpf and close() must tear it down */
  int bpf_owned;
} wired_srvxdp;

/** Open one AF_XDP-backed server socket with its own BPF redirect filter:
 * wired_srvxdpbpf_open on cfg->ifindex, then quic_xsksetup_open, then point
 * the map's queue_id slot at the new socket. The TX frame pool is
 * initialized over UMEM frames 64..127 (the RX pool, frames 0..63, is left
 * to the kernel's fill/rx rings). On any failure, everything already built
 * is torn down and a negative errno is returned. For multiple queues on one
 * interface, use wired_srvxdp_open_shared instead: the kernel rejects a
 * second XDP link on the same ifindex with -EBUSY.
 * @param x   zero-initialized output; filled in on success
 * @param cfg interface/queue/address/port and bind/attach flags
 * @return 0 on success, or a negative errno */
i64 wired_srvxdp_open(wired_srvxdp* x, const wired_srvxdp_cfg* cfg);

/** Open one AF_XDP-backed server socket against an already-open shared
 * per-interface BPF object: quic_xsksetup_open, then register the new
 * socket's fd in bpf's cfg->queue_id slot. x keeps no reference to bpf
 * afterwards (x->bpf stays -1/-1/-1, unowned): the caller owns bpf's
 * lifetime and must keep it open while any registered socket is in use.
 * On failure the socket is closed and a negative errno is returned.
 * @param x   zero-initialized output; filled in on success
 * @param cfg interface/queue/address/port and bind flags (attach_flags
 *            is unused: attachment happened in wired_srvxdpbpf_open)
 * @param bpf shared BPF objects for cfg->ifindex (wired_srvxdpbpf_open)
 * @return 0 on success, or a negative errno */
i64 wired_srvxdp_open_shared(
    wired_srvxdp* x, const wired_srvxdp_cfg* cfg, wired_srvxdpbpf* bpf);

/** Drain up to nbufs received datagrams into bufs. First reaps the
 * completion ring (returning any finished TX frames to txpool), then
 * consumes up to nbufs entries from the RX ring: each frame is parsed
 * (quic_xdpframe_parse), its payload copied into bufs[i].buf, its source
 * into bufs[i].src, and the peer's MAC learned into the reflect cache (the
 * first RX frame also seeds x->our_mac). Every consumed RX frame is
 * returned to the fill ring before this call returns.
 * @param x     open driver instance
 * @param bufs  array of nbufs receive slots
 * @param nbufs number of slots in bufs
 * @return number of datagrams written into bufs (0..nbufs) */
i64 wired_srvxdp_rx_burst(wired_srvxdp* x, quic_mmsg_buf* bufs, usz nbufs);

/** Send one datagram to dst. Drops (returns 0, letting QUIC retransmit)
 * when dst's MAC is not yet learned, or when the TX frame pool is
 * exhausted even after one completion-ring reap. On success, builds a
 * complete eth+IPv4+UDP frame around pkt into a TX-pool frame, submits it
 * to the TX ring, and kicks the kernel to service it (a kick failure is
 * ignored: tests exercising this without a real fd expect it to fail).
 * @param x   open driver instance
 * @param dst destination address
 * @param pkt the QUIC datagram to send
 * @return 1 sent, 0 dropped */
i64 wired_srvxdp_send(wired_srvxdp* x, const quic_sockaddr* dst, quic_span pkt);

/** Tear down x: close the owned BPF link/prog/map fds (skipped when x was
 * opened against a shared wired_srvxdpbpf, which the caller owns), then
 * quic_xsksetup_close the socket/rings/UMEM.
 * @param x driver instance to close */
void wired_srvxdp_close(wired_srvxdp* x);

/** Read XDP_STATISTICS for fd (quic_xsksetup_stats) and log one line per
 * counter (name + value) via wired_log_str. A no-op (silently returns) if
 * the stats read fails.
 *
 * @param fd the XDP socket file descriptor
 */
void wired_srvxdp_print_stats(i64 fd);

#endif
