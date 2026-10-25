#include "app/http3/server/srvboot/srvboot_impl.h"

static int srvboot_vn_sized(wired_span dg);
static int srvboot_vn_alien(u32 v, u32 versions);
static int srvboot_vn_owed(wired_span dg, u32 versions);
static int srvboot_vn_take_cid(wired_span dg, usz* off, wired_span* cid);
static int srvboot_vn_cids(wired_span dg, wired_span* dcid, wired_span* scid);

int wired_srvboot_accept(
    const wired_srvboot_conn* conn,
    const wired_srvboot_in*   in,
    wired_srvboot_out*        out) {
  wired_srvboot_acc a; /* single-datagram fast path, caller-stack lifetime */
  wired_srvboot_acc_reset(&a);
  if (!wired_srvboot_acc_feed(&a, in->dgram)) {
    return 0;
  }
  return wired_srvboot_accept_acc(conn, in->id, &a, out);
}

/* 1 if dg is big enough to owe a response and wears a long header
 * (RFC 9000 6: no Version Negotiation for a sub-1200-byte datagram). */
static int srvboot_vn_sized(wired_span dg) {
  return dg.n >= 1200 && (dg.p[0] & 0x80) != 0;
}

/* 1 if v is neither a Version Negotiation packet's 0 (RFC 9000 6.1) nor a
 * version this server accepts (RFC 9368 5 supported set, narrowed by the
 * application's WIRED_VERSIONS_* mask, RFC 9308 13). */
static int srvboot_vn_alien(u32 v, u32 versions) {
  vers_set s;
  if (v == 0) {
    return 0;
  }
  vers_init_mask(&s, versions);
  return !vers_supports(&s, v);
}

/* 1 if dg is a long-header datagram of an unsupported version. */
static int srvboot_vn_owed(wired_span dg, u32 versions) {
  return srvboot_vn_sized(dg) &&
         srvboot_vn_alien(be_get_be32(dg.p + 1), versions);
}

/* RFC 8999 5.1: one length-prefixed connection ID of 0..255 bytes at *off,
 * as a view into dg -- an unsupported version's IDs are not bounded by
 * QUIC v1's 20 bytes (RFC 9000 17.2: servers SHOULD read longer ones to
 * form a Version Negotiation packet). */
static int srvboot_vn_take_cid(wired_span dg, usz* off, wired_span* cid) {
  usz len;
  if (*off >= dg.n) {
    return 0;
  }
  len = dg.p[*off];
  if (len > dg.n - *off - 1) {
    return 0;
  }
  *cid = wired_span_of(dg.p + *off + 1, len);
  *off += 1 + len;
  return 1;
}

/* Both invariant-header connection IDs, right past byte0 + Version. */
static int srvboot_vn_cids(wired_span dg, wired_span* dcid, wired_span* scid) {
  usz off = 5; /* RFC 8999 5.1 */
  return srvboot_vn_take_cid(dg, &off, dcid) &&
         srvboot_vn_take_cid(dg, &off, scid);
}

usz wired_srvboot_vneg(wired_span dg, u32 versions, u8* out, usz cap) {
  vers_set   s;
  wired_span dcid, scid;
  if (!srvboot_vn_owed(dg, versions)) {
    return 0;
  }
  if (!srvboot_vn_cids(dg, &dcid, &scid)) {
    return 0;
  }
  vers_init_mask(&s, versions);
  return vneg_respond(out, cap, &(vneg_desc){dcid, scid, s.versions, s.n});
}
