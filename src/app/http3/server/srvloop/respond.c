#include "app/http3/server/srvloop/respond_impl.h"

static usz encode_ack_one(u8* frames, usz cap, u64 pn);

/* RFC 9000 13.2.1 / 19.3: encode an ACK frame for the single packet number pn.
 */
static usz encode_ack_one(u8* frames, usz cap, u64 pn) {
  ack_frame f    = {0};
  f.n_ranges     = 1;
  f.ranges[0].hi = pn;
  f.ranges[0].lo = pn;
  return ack_encode(frames, cap, &f);
}

/* RFC 9000 13.2.1: seal a Handshake packet that carries only an ACK of the
 * client Finished's actual packet number (no CRYPTO), so curl stops
 * retransmitting it. The PN is recorded by note_hs_rx as packets arrive; curl
 * leads with an ACK-only Handshake packet, so the Finished is not at PN 0 and a
 * fixed ACK of 0 left it unacknowledged — the client then PTO-retransmitted it
 * for ~4s before the handshake completed (the appconnect stall). */
int srvloop_emit_handshake_ack(const wired_srvloop_conn* c, wired_obuf* out) {
  wired_srvloop_dirkeys dk;
  u8                    frames[16];
  usz                   fl;
  if (!wired_srvloop_seal_keys(c->s, LEVEL_HANDSHAKE, &dk)) {
    return 0;
  }
  fl = encode_ack_one(frames, sizeof frames, c->l->hs_rx_pn);
  if (fl == 0) {
    return 0;
  }
  protect_keys pk = {dk.keys, &dk.hp};
  hspkt_desc   d  = {
      wired_span_of(c->l->cli_scid, c->l->cli_scid_len),
      wired_span_of(c->s->sdrv.iscid, c->s->sdrv.iscid_len), c->l->hs_tx_pn++,
      wired_span_of(frames, fl), sdrv_wire_version(&c->s->sdrv)};
  /* out->len 0 unless built */
  return hspkt_build_suite(c->s->sdrv.cipher_suite, &pk, &d, out);
}
