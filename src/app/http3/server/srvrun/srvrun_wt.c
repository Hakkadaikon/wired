#include "app/http3/server/srvrun/srvrun_impl.h"

static int srvrun_boot_salvage(const srvrun_conn* c);

/* Feed dg into c's boot accumulator, restarting it for a fresh attempt (a
 * just-claimed slot, or a confirmed connection re-cold-starting). The
 * datagram's ECN codepoint is counted after any reset -- the accept
 * flight's Initial ACK must carry the ClientHello datagram's own mark
 * (RFC 9000 13.4.1: the peer validates against its FIRST acknowledgment). */
int srvrun_boot_feed(srvrun_conn* c, wired_mspan dg, u8 ecn) {
  if (c->up || !c->boot.any) {
    wired_srvboot_acc_reset(&c->boot);
  }
  wired_srvboot_acc_ecn_note(&c->boot, ecn);
  return wired_srvboot_acc_feed(&c->boot, dg);
}

/* First datagram(s) on this slot: reassemble the ClientHello across Initial
 * datagrams and cold-start the connection once it is whole (the server
 * Initial is padded to 1200 bytes, RFC 9000 14.1, so the flight is sent as
 * separate datagrams). Returns 1 once the connection is up, 0 on a failed
 * boot, SRVRUN_BOOT_PENDING while more ClientHello is owed. */
/* A refused datagram settles a claim that never authenticated anything
 * (junk unclaims immediately) but does not tear down a boot that has real
 * packets absorbed — spoofed garbage must not kill a half-open handshake. */
static int srvrun_boot_salvage(const srvrun_conn* c) {
  return c->boot.opened ? SRVRUN_BOOT_PENDING : 0;
}

int srvrun_on_initial(
    const srvrun_step_ctx* ctx, int slot, srvrun_conn* c, wired_mspan dg) {
  if (!srvrun_boot_feed(c, dg, ctx->ecn)) {
    return srvrun_boot_salvage(c);
  }
  if (!wired_srvboot_acc_complete(&c->boot)) {
    return SRVRUN_BOOT_PENDING;
  }
  return srvrun_boot_finish(ctx, slot, c, dg);
}

/* One standard RESET_STREAM (RFC 9000 19.4) at plb->p + at, its Final Size
 * the bytes already sent on stream_id's send slot (0 for a stream this
 * server never replied on). Nothing (0 bytes) for a stream whose send part
 * already ended: RFC 9000 3.1 has no reset past "Data Recvd", and RFC 9000
 * 4.5 makes a Final Size below the bytes the peer has a FINAL_SIZE_ERROR. */
usz srvrun_wt_abort_reset(
    srvrun_conn* c, u64 stream_id, u64 err_code, wired_obuf* plb, usz at) {
  reset_stream_frame rs = {
      stream_id, err_code, srvrun_wtsend_final_size(c, stream_id)};
  if (srvrun_wt_send_ended(c, stream_id)) {
    return 0;
  }
  return reset_stream_encode(plb->p + at, plb->cap - at, &rs);
}

/* One STOP_SENDING (RFC 9000 19.5) at plb->p + at. */
usz srvrun_wt_abort_stop(u64 stream_id, u64 err_code, wired_obuf* plb, usz at) {
  stop_sending_frame ss = {stream_id, err_code};
  return stop_sending_encode(plb->p + at, plb->cap - at, &ss);
}

/* RESET_STREAM followed by STOP_SENDING -- the full abort of a bidi
 * stream's both halves, same pair shape as h3cancel_request (STOP_SENDING
 * alone once the send half already ended, srvrun_wt_abort_reset). */
usz srvrun_wt_abort_pair(
    srvrun_conn* c, u64 stream_id, u64 err_code, wired_obuf* plb) {
  /* rn == 0 only means the send part ended: every caller's plb (48 bytes,
   * srvrun_send_wt_busy_reset) fits one RESET_STREAM (type + 3 varints,
   * at most 25 bytes), so it is never an encode failure. */
  usz rn = srvrun_wt_abort_reset(c, stream_id, err_code, plb, 0);
  usz sn = srvrun_wt_abort_stop(stream_id, err_code, plb, rn);
  if (!sn) {
    return 0;
  }
  return rn + sn;
}

/* RFC 9114 4.1.1/8.1: a server aborts a stream with the frames RFC 9000
 * 19.4/19.5 allow it to send FOR THAT STREAM'S TYPE, carrying err_code --
 * an HTTP/3-level code (e.g. H3_REQUEST_REJECTED) or a WebTransport
 * application code already mapped through wired_wterrmap_to_http3:
 *
 * - bidi (either initiator): RESET_STREAM + STOP_SENDING, both halves.
 * - client uni: STOP_SENDING alone. This server has no send part, and a
 *   RESET_STREAM arriving for what the client sees as its send-only stream
 *   is a connection-fatal STREAM_STATE_ERROR at the client.
 * - server uni: RESET_STREAM alone. The client cannot send on it, and a
 *   STOP_SENDING arriving for what the client sees as a receive-only
 *   stream is likewise connection-fatal (RFC 9000 19.5).
 *
 * Standard RESET_STREAM (0x04), never RESET_STREAM_AT (0x24): 0x24 is a
 * draft-ietf-quic-reliable-stream-reset extension frame this SDK never
 * negotiates, so a peer (Chrome included) treats it as an unknown frame
 * and kills the whole connection with FRAME_ENCODING_ERROR. */
usz srvrun_wt_busy_reset_payload(
    srvrun_conn* c, u64 stream_id, u64 err_code, wired_obuf* plb) {
  if (!stream_can_send(0, stream_id)) { /* client uni */
    return srvrun_wt_abort_stop(stream_id, err_code, plb, 0);
  }
  if (!stream_can_receive(0, stream_id)) { /* server uni */
    return srvrun_wt_abort_reset(c, stream_id, err_code, plb, 0);
  }
  return srvrun_wt_abort_pair(c, stream_id, err_code, plb);
}

/* Seal the pln control-frame bytes at pl (0: nothing built) into out as
 * their own 1-RTT packet. Returns 1 with out->len set, 0 on failure. */
int srvrun_seal_ctl(srvrun_conn* c, const u8* pl, usz pln, wired_obuf* out) {
  wired_srvloop_send_in sin = {
      wired_span_of(c->l.cli_scid, c->l.cli_scid_len),
      0,
      -1,
      wired_span_of(pl, pln),
      0,
      0,
      0,
      0};
  if (!pln) {
    return 0;
  }
  sin.pn = c->l.tx_pn++;
  return wired_srvloop_send_onertt(&c->s, &sin, out);
}

/* Seal pl as its own 1-RTT packet into out, kept for resending until ACKed
 * (RFC 9000 13.3). Returns 1 with out->len set, 0 on failure. */
int srvrun_seal_kept(srvrun_conn* c, const u8* pl, usz pln, wired_obuf* out) {
  srvrun_rst_keep(c, pl, pln);
  return srvrun_seal_ctl(c, pl, pln, out);
}
