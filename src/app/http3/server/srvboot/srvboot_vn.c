#include "app/http3/server/srvboot/srvboot_impl.h"

static int srvboot_vn_sized(wired_span dg);
static int srvboot_vn_alien(u32 v);
static int srvboot_vn_owed(wired_span dg);

int wired_srvboot_accept(
    const wired_srvboot_conn* conn,
    const wired_srvboot_in*   in,
    wired_srvboot_out*        out) {
  wired_srvboot_acc a; /* single-datagram fast path, caller-stack lifetime */
  wired_srvboot_acc_reset(&a);
  if (!wired_srvboot_acc_feed(&a, in->dgram)) return 0;
  return wired_srvboot_accept_acc(conn, in->id, &a, out);
}

/* 1 if dg is big enough to owe a response and wears a long header
 * (RFC 9000 6: no Version Negotiation for a sub-1200-byte datagram). */
static int srvboot_vn_sized(wired_span dg) {
  return dg.n >= 1200 && (dg.p[0] & 0x80) != 0;
}

/* 1 if v is neither a Version Negotiation packet's 0 (RFC 9000 6.1) nor a
 * version this server speaks (RFC 9368 5 supported set: v1, v2). */
static int srvboot_vn_alien(u32 v) {
  vers_set s;
  if (v == 0) return 0;
  vers_init(&s);
  return !vers_supports(&s, v);
}

/* 1 if dg is a long-header datagram of an unsupported version. */
static int srvboot_vn_owed(wired_span dg) {
  return srvboot_vn_sized(dg) && srvboot_vn_alien(be_get_be32(dg.p + 1));
}

usz wired_srvboot_vneg(wired_span dg, u8* out, usz cap) {
  vers_set     s;
  wired_header h;
  vneg_desc    d;
  if (!srvboot_vn_owed(dg)) return 0;
  if (!wired_header_parse(dg.p, dg.n, &h)) return 0;
  vers_init(&s);
  d = (vneg_desc){
      wired_span_of(h.dcid, h.dcid_len), wired_span_of(h.scid, h.scid_len),
      s.versions, s.n};
  return vneg_respond(out, cap, &d);
}
