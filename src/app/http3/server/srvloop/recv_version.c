#include "app/http3/server/srvloop/recv.h"
#include "common/bytes/util/be.h"
#include "transport/packet/header/packet/ptype.h"
#include "transport/version/version/version.h"

/* RFC 8999 5.1: the Version field of a long header. A short header carries
 * none -- 1-RTT is always in the connection's negotiated version. */
u32 srvloop_recv_pkt_version(const wired_server* s, wired_mspan dg) {
  if (dg.n < 5 || !packet_is_long(dg.p[0])) {
    return sdrv_wire_version(&s->sdrv);
  }
  return be_get_be32(dg.p + 1);
}

/* The client's original version: its first Initial's (RFC 9368 2.2). */
static u32 srvloop_recv_orig_version(const wired_server* s) {
  return s->sdrv.client_version ? s->sdrv.client_version : VERSION_1;
}

/* RFC 9369 4.1: the original version still carries 0-RTT (a client never
 * sends 0-RTT in the negotiated version) and Initials until a Handshake
 * packet -- necessarily in the negotiated version -- has been processed. */
static int srvloop_recv_orig_type_ok(const wired_server* s, int type) {
  return type == PT_0RTT || (type == PT_INITIAL && !s->hs_rx_seen);
}

static int srvloop_recv_orig_ok(const wired_server* s, u32 ver, int type) {
  return ver == srvloop_recv_orig_version(s) &&
         srvloop_recv_orig_type_ok(s, type);
}

/* RFC 9369 4.1: Initial, Handshake and 1-RTT packets in the negotiated
 * version; 0-RTT never is (recv_orig_ok's alone). */
static int srvloop_recv_wire_ok(const wired_server* s, u32 ver, int type) {
  return type != PT_0RTT && ver == sdrv_wire_version(&s->sdrv);
}

/* RFC 9369 4.1: "An endpoint MUST drop packets using any other version." */
int srvloop_recv_version_ok(const wired_server* s, u32 ver, int type) {
  return srvloop_recv_orig_ok(s, ver, type) ||
         srvloop_recv_wire_ok(s, ver, type);
}
