/* RFC 9000 9: a connection survives a change of its peer's address, but
 * with several AF_XDP queues the new 4-tuple (migration, NAT rebinding) or
 * a changed NIC RSS table puts its packets on another queue, and the XDP
 * filter can only redirect a frame to the XSK of the queue it arrived on
 * (xdpbpf.h). So the receiving worker reads the owner from the short
 * header's DCID (the worker byte every issued CID carries, srvrun_claim.c)
 * and hands the datagram to the owner through the srvfwd mesh; the owner
 * serves it as if its own socket had received it, source address
 * included, so path validation (RFC 9000 8.2, 9.3) runs as usual. Long
 * headers stay where they land: a handshake cannot migrate (RFC 9000 9)
 * and a client's first Initial DCID is random (RFC 9000 7.2). */

#include "app/http3/server/srvxdp/srvxdp_impl.h"

static int srvxdp_fwd_on(const wired_srvxdp* x, const xdpframe_rx* rx);
static int srvxdp_fwd_other(const wired_srvxdp* x, u32 owner);
static const xdpframe_rx* srvxdp_fwd_next(srvfwd_ring* r, u32 got, u32 max);
static u32                srvxdp_fwd_drain_ring(
    wired_srvxdp* x, srvfwd_ring* r, mmsg_buf* bufs, u32 max);

/* Forwarding is on and rx is a short header (RFC 9000 17.3: Header Form 0)
 * long enough for the DCID's routing bytes. */
static int srvxdp_fwd_on(const wired_srvxdp* x, const xdpframe_rx* rx) {
  return x->fwd && rx->payload_len > NCID_ROUTE_MIN_LEN &&
         !(rx->payload[0] & 0x80);
}

/* owner is another worker of the mesh (a byte naming no worker is served
 * here: that CID was not issued by this server). */
static int srvxdp_fwd_other(const wired_srvxdp* x, u32 owner) {
  return owner < x->fwd_n && owner != x->queue_id;
}

int srvxdp_fwd_handoff(wired_srvxdp* x, const xdpframe_rx* rx) {
  u32 owner;
  if (!srvxdp_fwd_on(x, rx)) {
    return 0;
  }
  owner = ncid_route_decode(rx->payload + 1, &x->route_key);
  if (!srvxdp_fwd_other(x, owner)) {
    return 0;
  }
  srvfwd_push(&x->fwd[(usz)owner * x->fwd_n + x->queue_id], rx);
  return 1;
}

static const xdpframe_rx* srvxdp_fwd_next(srvfwd_ring* r, u32 got, u32 max) {
  return got < max ? srvfwd_peek(r) : 0;
}

/* Deliver up to max datagrams from one ring of this worker's row. */
static u32 srvxdp_fwd_drain_ring(
    wired_srvxdp* x, srvfwd_ring* r, mmsg_buf* bufs, u32 max) {
  u32 got = 0;
  for (const xdpframe_rx* rx = srvxdp_fwd_next(r, got, max); rx;
       rx                    = srvxdp_fwd_next(r, got, max)) {
    got += (u32)srvxdp_rx_deliver(x, rx, &bufs[got]);
    srvfwd_pop(r);
  }
  return got;
}

/* Each call starts one ring further along the row, so a busy producer
 * cannot keep the budget from the others. */
u32 srvxdp_fwd_drain(wired_srvxdp* x, mmsg_buf* bufs, u32 max) {
  u32          got   = 0;
  u32          start = x->fwd_next;
  srvfwd_ring* row;
  if (!x->fwd) {
    return 0;
  }
  row         = x->fwd + (usz)x->queue_id * x->fwd_n;
  x->fwd_next = (start + 1) % x->fwd_n;
  for (u32 k = 0; k < x->fwd_n; k++) {
    u32 j = (start + k) % x->fwd_n;
    got += srvxdp_fwd_drain_ring(x, &row[j], bufs + got, max - got);
  }
  return got;
}
