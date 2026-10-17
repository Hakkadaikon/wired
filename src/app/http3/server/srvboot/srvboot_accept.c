#include "app/http3/server/srvboot/srvboot_impl.h"

static void srvboot_arm_pref_addr(
    const wired_srvboot_conn* conn, const wired_srvboot_id* id);
static int srvboot_acc_start(
    const wired_srvboot_conn* conn,
    const wired_srvboot_id*   id,
    wired_srvboot_acc*        a);
static usz srvboot_ch1_total(const wired_srvboot_acc* a);
static int srvboot_hrr(
    const wired_srvboot_conn* conn,
    wired_srvboot_acc*        a,
    wired_srvboot_out*        out);
static int srvboot_accept_reply(
    const wired_srvboot_conn* conn,
    const wired_srvboot_id*   id,
    wired_srvboot_acc*        a,
    wired_srvboot_out*        out);
static u64 srvboot_refusal_error(u64 error_code);

/* RFC 9000 9.6: arm the preferred_address transport parameter when the
 * operator configured one AND this connection drew a spare CID to migrate
 * with -- the parameter's CID slot carries the spare (sequence 1), so the
 * confirmation flight's NEW_CONNECTION_ID frame stands down for it
 * (spare_cid_in_tp; see respond.c's append_ncid_frame). */
static void srvboot_arm_pref_addr(
    const wired_srvboot_conn* conn, const wired_srvboot_id* id) {
  sdrv_pref_addr p;
  if (!id->pref_v4 || !conn->l->spare_cid_len) {
    return;
  }
  p = (sdrv_pref_addr){
      id->pref_v4,
      id->pref_v4_port,
      id->pref_v6,
      id->pref_v6_port,
      conn->l->spare_cid,
      conn->l->spare_cid_len,
      conn->l->spare_cid_token};
  sdrv_set_preferred_address(&conn->s->sdrv, &p);
  conn->l->spare_cid_in_tp = 1;
}

/* Init the server/loop from the bound header and fold the reassembled
 * ClientHello. After a HelloRetryRequest the server/loop are already
 * initialized (re-running wired_server_init would erase the driver's
 * hrr_sent state) and the message to fold is ClientHello2 at hrr_off. */
static int srvboot_acc_start(
    const wired_srvboot_conn* conn,
    const wired_srvboot_id*   id,
    wired_srvboot_acc*        a) {
  wired_span ch;
  crecv_message_at(&a->cr, a->hrr_off, &ch.p, &ch.n);
  if (a->hrr_off == 0 && !srvboot_init(conn, id, &a->hdr)) {
    return 0;
  }
  /* RFC 9368 2.2: the version the client's first Initial arrived in --
   * the baseline sdrv validates its version_information's Chosen against
   * and replies in when nothing better is negotiated. */
  sdrv_set_client_version(&conn->s->sdrv, a->hdr.version);
  srvboot_arm_pref_addr(conn, id);
  return wired_server_recv_initial(conn->s, ch.p, ch.n);
}

/* RFC 8446 4: the full length (header included) of the leading handshake
 * message in the accumulator -- ClientHello1's size, which is where the
 * retried ClientHello2 starts on the crypto stream. */
static usz srvboot_ch1_total(const wired_srvboot_acc* a) {
  const u8* ch;
  usz       n;
  crecv_message(&a->cr, &ch, &n);
  return 4 + ((usz)ch[1] << 16 | (usz)ch[2] << 8 | ch[3]);
}

/* RFC 8446 4.1.4: seal the HelloRetryRequest the just-folded ClientHello1
 * owes as one server Initial (pn 1 -- the slot the accept flight would have
 * used; the eventual post-retry flight takes a fresh pn instead), acking
 * ClientHello1's packet number, and arm the accumulator for ClientHello2. */
static int srvboot_hrr(
    const wired_srvboot_conn* conn,
    wired_srvboot_acc*        a,
    wired_srvboot_out*        out) {
  u8                    hrr[SRVBOOT_SH_MAX];
  wired_obuf            hob = obuf_of(hrr, sizeof hrr);
  wired_srvloop_send_in in0;
  if (!wired_server_build_hrr(conn->s, &hob)) {
    return 0;
  }
  in0 = (wired_srvloop_send_in){
      wired_span_of(conn->l->cli_scid, conn->l->cli_scid_len),
      1,
      (i64)a->largest_pn,
      wired_span_of(hrr, hob.len),
      0,
      a->ecn_ect0,
      a->ecn_ect1,
      a->ecn_ce};
  /* RFC 9368 2.3: the HelloRetryRequest is part of the server's first
   * flight, so it already goes out in the negotiated compatible version. */
  if (!wired_srvloop_send_initial_ver(
          sdrv_wire_version(&conn->s->sdrv), conn->s, &in0, out->initial)) {
    return 0;
  }
  a->hrr_off       = srvboot_ch1_total(a);
  a->ini_tx_off    = hob.len; /* the ServerHello continues past the HRR */
  out->dgram_count = 0;       /* no Handshake flight yet -- Initial only */
  return WIRED_SRVBOOT_HRR;
}

/* The accumulator is complete and folded -- seal what the driver decided:
 * a HelloRetryRequest (no usable key_share offered) or the accept flight. */
static int srvboot_accept_reply(
    const wired_srvboot_conn* conn,
    const wired_srvboot_id*   id,
    wired_srvboot_acc*        a,
    wired_srvboot_out*        out) {
  out->client_pn = a->largest_pn;
  if (sdrv_hrr_pending(&conn->s->sdrv)) {
    return srvboot_hrr(conn, a, out);
  }
  return srvboot_flight(conn, id, a, out);
}

int wired_srvboot_accept_acc(
    const wired_srvboot_conn* conn,
    const wired_srvboot_id*   id,
    wired_srvboot_acc*        a,
    wired_srvboot_out*        out) {
  if (!wired_srvboot_acc_complete(a)) {
    return 0;
  }
  if (!srvboot_acc_start(conn, id, a)) {
    return 0;
  }
  return srvboot_accept_reply(conn, id, a, out);
}

/* error_code, or the generic fallback when the caller had no specific
 * cause (0). */
static u64 srvboot_refusal_error(u64 error_code) {
  if (error_code) {
    return error_code;
  }
  return SRVBOOT_REFUSAL_DEFAULT_ERROR;
}

usz wired_srvboot_refusal(
    const wired_srvboot_acc* a,
    wired_span               scid,
    u64                      error_code,
    u8*                      out,
    usz                      cap) {
  u8               fr[8];
  conn_close_frame f  = {0, srvboot_refusal_error(error_code), 0, 0, 0};
  usz              fn = frame_put_conn_close(fr, sizeof fr, &f);
  wired_obuf       ob = obuf_of(out, cap);
  srvwire_seal_in  wi = {
      wired_span_of(a->hdr.dcid, a->hdr.dcid_len),
      wired_span_of(a->hdr.scid, a->hdr.scid_len),
      scid,
      1,
      (i64)a->largest_pn,
      wired_span_of(fr, fn),
      0,
      0,
      0,
      0,
      a->hdr.version};
  if (fn == 0) {
    return 0;
  }
  if (!srvwire_seal_initial_frames(&wi, &ob)) {
    return 0;
  }
  return ob.len;
}
