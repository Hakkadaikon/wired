#include "app/http3/server/srvloop/keys.h"
#include "app/http3/server/srvrun/srvrun_impl.h"
#include "transport/packet/build/hspkt/hspkt_build.h"

/* RFC 9000 10.2.3: the close frame for an Initial or Handshake packet. An
 * application close (0x1d) must not go out at those levels, so it becomes
 * a transport close (0x1c) carrying APPLICATION_ERROR and no reason; a
 * transport close is copied as is. fr holds SRVRUN_CLOSE_PL_MAX bytes. */
usz srvrun_close_long_frame(const srvrun_conn* c, u8* fr) {
  conn_close_frame f = {0, ERR_APPLICATION_ERROR, 0, 0, 0};
  if (c->close_pl[0] != FRAME_CONN_CLOSE_APP) {
    bytes_memcpy(fr, c->close_pl, c->close_pln);
    return c->close_pln;
  }
  return frame_put_conn_close(fr, SRVRUN_CLOSE_PL_MAX, &f);
}

/* Seal fr as its own Handshake packet under the next Handshake pn. */
static int srvrun_seal_close_hs(
    srvrun_conn* c, wired_span fr, wired_obuf* out) {
  wired_srvloop_dirkeys dk;
  protect_keys          pk;
  hspkt_desc            d = {
      wired_span_of(c->l.cli_scid, c->l.cli_scid_len),
      wired_span_of(c->s.sdrv.iscid, c->s.sdrv.iscid_len), 0, fr,
      sdrv_wire_version(&c->s.sdrv)};
  if (!wired_srvloop_seal_keys(&c->s, LEVEL_HANDSHAKE, &dk)) {
    return 0;
  }
  pk   = (protect_keys){dk.keys, &dk.hp};
  d.pn = c->l.hs_tx_pn++;
  return hspkt_build_suite(c->s.sdrv.cipher_suite, &pk, &d, out);
}

/* Seal fr as its own Initial packet under the next unused Initial pn. A
 * CONNECTION_CLOSE is not ack-eliciting, so no 1200-byte padding (RFC 9000
 * 14.1) -- the antiamp budget of an unvalidated path stays untouched. */
static int srvrun_seal_close_ini(
    srvrun_conn* c, wired_span fr, wired_obuf* out) {
  srvwire_seal_in wi = {
      wired_span_of(c->s.sdrv.odcid, c->s.sdrv.odcid_len),
      wired_span_of(c->l.cli_scid, c->l.cli_scid_len),
      wired_span_of(c->s.sdrv.iscid, c->s.sdrv.iscid_len),
      c->ini_next_pn++,
      -1,
      fr,
      0,
      0,
      0,
      0,
      sdrv_wire_version(&c->s.sdrv)};
  return srvwire_seal_initial_frames_lean(&wi, out);
}

typedef int (*srvrun_close_sealer)(srvrun_conn*, wired_span, wired_obuf*);

/* Seal fr with seal and send it; nothing goes out if sealing fails. */
static void srvrun_close_long_send(
    const srvrun_cfg*   cfg,
    srvrun_conn*        c,
    wired_span          fr,
    srvrun_close_sealer seal) {
  u8         out[MIN_INITIAL_DATAGRAM];
  wired_obuf ob = obuf_of(out, sizeof out);
  if (seal(c, fr, &ob)) {
    srvrun_send_now(
        cfg, c, wired_span_of(out, ob.len), "CONNECTION_CLOSE sent\n");
  }
}

/* RFC 9000 10.2.3: before the handshake is confirmed the peer may not have
 * 1-RTT keys yet, so the close also goes out in a Handshake packet, and in
 * an Initial packet while the Initial keys are still live (no client
 * Handshake packet processed yet, RFC 9001 4.9.1). The 1-RTT copy the
 * caller seals next needs the 0.5-RTT send keys (RFC 9001 4.9), installed
 * here. */
void srvrun_close_send_long(const srvrun_cfg* cfg, srvrun_conn* c) {
  u8         fr[SRVRUN_CLOSE_PL_MAX];
  wired_span f = wired_span_of(fr, srvrun_close_long_frame(c, fr));
  if (wired_server_is_confirmed(&c->s)) {
    return;
  }
  (void)wired_server_early_send_keys(&c->s);
  if (srvrun_initial_live(c)) {
    srvrun_close_long_send(cfg, c, f, srvrun_seal_close_ini);
  }
  srvrun_close_long_send(cfg, c, f, srvrun_seal_close_hs);
}
