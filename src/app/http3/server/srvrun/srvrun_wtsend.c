#include "app/http3/server/srvrun/srvrun_impl.h"

static usz srvrun_qenc_prefix(u8* out, usz cap);
static int srvrun_qenc_claim_and_arm(srvrun_conn* c, const u8* prefix, usz n);

/* Claim the first free WT send slot on c with the given stream credit seed
 * (RFC 9000 18.2/19.10; MAX_STREAM_DATA later raises it via
 * srvrun_apply_stream_credit_update). 0 when every slot is busy. */
srvrun_wtsend* srvrun_wtsend_claim(srvrun_conn* c, u64 credit) {
  for (usz i = 0; i < SRVRUN_WT_SEND_SLOTS; i++) {
    if (!c->wtsend[i].in_use) {
      return srvrun_wtsend_take(&c->wtsend[i], credit);
    }
  }
  return 0;
}

/* RFC 9000 2.1: allocate the next server-initiated stream id. Called only
 * after a send slot has been claimed, so a failed open never burns an id. */
u64 srvrun_next_uni_id(srvrun_conn* c) {
  /* HTTP/3: id 3 = H3 control stream, 7 = QPACK encoder stream, 11 = QPACK
   * decoder stream (srvrun_open_qpack_streams, opened once outside this
   * counter) -- WT uni streams start at 15. Raw QUIC has none of them, so
   * they start at 3. */
  return rawq_uni_first_id(srvrun_conn_is_raw(c)) + 4 * c->wt_uni_opened++;
}

/* RFC 9000 4.6: the peer's current uni-stream grant for server-initiated
 * streams -- the highest runtime MAX_STREAMS(uni) raise, or the
 * ClientHello's initial_max_streams_uni before any raise. Counts every uni
 * stream this server opened, H3 plumbing included (wt_uni_opened's id
 * arithmetic starts past the control + QPACK streams on HTTP/3:
 * those three always count, srvrun_uni_plumbing). */
u64 srvrun_peer_uni_limit(const srvrun_conn* c) {
  return c->peer_uni_stream_limit ? c->peer_uni_stream_limit
                                  : c->s.sdrv.peer_initial_max_streams_uni;
}

/* RFC 9000 19.11: fold this step's gathered MAX_STREAMS(uni) high-water
 * mark into the connection's limit -- monotone, a stale lower raise never
 * lowers it (mirrors srvrun_apply_conn_credit_update's shape). */
void srvrun_apply_uni_limit_update(srvrun_conn* c) {
  if (!c->l.max_streams_uni_seen_flag) {
    return;
  }
  c->l.max_streams_uni_seen_flag = 0;
  if (c->l.max_streams_uni_seen > c->peer_uni_stream_limit) {
    c->peer_uni_stream_limit = c->l.max_streams_uni_seen;
  }
}

/* Server uni streams opened outside wt_uni_opened: HTTP/3's control (3) and
 * QPACK encoder (7) and decoder (11) -- the ids below the first application
 * id -- and none on raw QUIC (rawq_uni_first_id: 15 vs 3, RFC 9000 2.1 steps
 * of 4). */
u64 srvrun_uni_plumbing(const srvrun_conn* c) {
  return (rawq_uni_first_id(srvrun_conn_is_raw(c)) - RAWQ_UNI_FIRST_RAW) / 4;
}

/* 1 iff the peer's uni-stream limit admits one more server-initiated open:
 * wt_uni_opened counts opens past the plumbing streams (srvrun_uni_plumbing)
 * -- on HTTP/3 the control stream (id 3) and the QPACK encoder (7) and
 * decoder (11) streams, which together consumed the first three grants. */
int srvrun_uni_open_allowed(const srvrun_conn* c) {
  return maxstreams_can_open(
      c->wt_uni_opened + srvrun_uni_plumbing(c), srvrun_peer_uni_limit(c));
}

u64 srvrun_next_bidi_id(srvrun_conn* c) { return 1 + 4 * c->wt_bidi_opened++; }

/* Arm w over payload on stream id: a payload that fits w's own round
 * buffer is COPIED (the caller's storage may be reused the moment this
 * returns), a larger one is held as a view under srvrun.h's keep-alive
 * contract. The pump takes it from the connection's next step/tick under
 * the shared cwnd/credit/pacing gates. */
i64 srvrun_wtsend_arm_id(
    const srvrun_conn* c, srvrun_wtsend* w, u64 id, wired_span payload) {
  const u8* src = payload.p;
  w->view_round = payload.n > SRVRUN_WTSEND_BUF;
  if (!w->view_round) {
    bytes_memcpy(w->roundbuf, payload.p, payload.n);
    src = w->roundbuf;
  }
  w->stream_id  = id;
  w->stream_off = payload.n;
  wired_sendsess_arm(&w->sess, src, payload.n, srvrun_mps(c));
  /* roundbuf epochs are rings (see srvrun_wtsend_stage_round); a view round
   * stays linear -- its bytes live in the app's storage, not roundbuf. */
  if (!w->view_round) {
    wired_sendq_set_ring(&w->sess.q, SRVRUN_WTSEND_BUF);
  }
  return (i64)id;
}

/* RFC 9204 4.2: the encoder stream's one-byte leading stream type -- no
 * SETTINGS-equivalent header follows (unlike the H3 control stream), the
 * type byte alone marks the stream and every subsequent byte is QPACK
 * encoder-stream instructions (Insert/Duplicate/Set Capacity). */
static usz srvrun_qenc_prefix(u8* out, usz cap) {
  usz off = 0;
  if (!varint_put(wired_mspan_of(out, cap), &off, H3_STREAM_QPACK_ENCODER)) {
    return 0;
  }
  return off;
}

/* RFC 9204 4.2: open this connection's ONE QPACK encoder stream (id
 * SRVRUN_QENC_STREAM) once, right after SETTINGS is confirmed sent --
 * claims a wtsend slot exactly like a WT uni open (srvrun_wt_open_uni_
 * common), but outside wt_uni_opened's id counter and its WT-session flow
 * gates: this is server plumbing, not an app-driven WebTransport stream, and
 * it never closes (append_open stays 1 for the connection's whole life). A
 * claim failure (every wtsend slot busy) leaves qenc_stream_opened 0, so a
 * later step retries rather than silently going without an encoder stream
 * forever. */
/* Claim a wtsend slot and arm it over the encoder stream's n-byte prefix,
 * recording c's own opened state. Returns 1 on success, 0 if every wtsend
 * slot is busy (c is left unchanged, a later step retries). Split from
 * srvrun_open_qenc_stream so its own branch count stays inside the CCN
 * gate. */
static int srvrun_qenc_claim_and_arm(srvrun_conn* c, const u8* prefix, usz n) {
  srvrun_wtsend* w =
      srvrun_wtsend_claim(c, c->s.sdrv.peer_initial_max_stream_data_uni);
  if (!w) {
    return 0;
  }
  w->append_open = 1;
  srvrun_wtsend_arm_id(c, w, SRVRUN_QENC_STREAM, wired_span_of(prefix, n));
  c->qenc_wtsend_slot   = (int)(w - c->wtsend);
  c->qenc_stream_opened = 1;
  return 1;
}

/* 1 iff the QPACK encoder stream prefix wrote 1..cap bytes. */
static int srvrun_qenc_prefix_ok(usz n, usz cap) { return n != 0 && n <= cap; }

void srvrun_open_qenc_stream(srvrun_conn* c) {
  u8  prefix[1];
  usz n = srvrun_qenc_prefix(prefix, sizeof prefix);
  if (c->qenc_stream_opened) {
    return;
  }
  if (!srvrun_qenc_prefix_ok(n, sizeof prefix)) {
    return;
  }
  srvrun_qenc_claim_and_arm(c, prefix, n);
}

/* Not open yet, and the peer's uni limit admits a third server stream (RFC
 * 9000 4.6: one past it is a STREAM_LIMIT_ERROR; a peer granting fewer
 * breaks RFC 9114 6.2, so it waits for a MAX_STREAMS raise). */
int srvrun_qdec_open_due(const srvrun_conn* c) {
  return !c->qdec_stream_opened &&
         maxstreams_can_open(2, srvrun_peer_uni_limit(c));
}
