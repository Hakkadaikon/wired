/* draft-23 REQUEST_UPDATE ordering and credit (9.5, 9.5.1, 9.1.7): updates
 * are decided and answered one by one in the order they arrive; a failed
 * one ends its request, so later updates on the stream are dropped
 * unanswered -- yet they keep counting against MAX_REQUEST_UPDATES, and a
 * flushed reply credits back only the updates it answers. Earlier drafts
 * keep answering after a failure (each check names its draft side). */

/* ===================== fixtures ===================== */

/* Types of the REQUEST_OK / REQUEST_ERROR replies that left on request
 * stream sid, in order, into t (up to n); their count. Refused sends are
 * skipped: the retry that goes out is the one the peer reads. */
static usz mtuo_replies(u64 sid, u64* t, usz n) {
  usz k = 0;
  for (usz i = 0; i < g_n_calls; i++) {
    const moqtrun_test_call* c = &g_calls[i];
    if ((c->kind != 12 && c->kind != 3) || c->stream_id != sid || c->refused) {
      continue;
    }
    wired_span b   = wired_span_of(c->payload, c->payload_len);
    usz        off = 0;
    u64        type;
    wired_span body;
    while (k < n && off < b.n &&
           mt_peek_type(b, &off, &type, &body) == MOQCTL_OK) {
      if (type == MOQCTL_T_REQUEST_OK || type == MOQCTL_T_REQUEST_ERROR) {
        t[k++] = type;
      }
    }
  }
  return k;
}

static usz mtuo_n(void) {
  u64 t[64]; /* the longest schedule's replies (every_update_resolved) */
  return mtuo_replies(MTRQ_S1, t, 64);
}

/* B subscribes the hub's blob on MTRQ_S1 with FORWARD 0. */
static void mtuo_sub(void) {
  moqctl_params p0 = mtst_params_u8(MOQCTL_PARAM_FORWARD, 0);
  moqctl_ftn    m  = mtst_ftn("chat", "room1", "movie");
  mtrq_setup();
  CHECK(moqtrun_test_publish_small_blob(&mtst_hub, 10) != 0);
  mtst_subscribe_p(SESS_B, MTRQ_S1, &m, 2, &p0);
}

static wired_moqtrun_sub* mtuo_s(void) {
  return moqtrun_track_sub_of_peer(&mtst_hub.blob_track, mtst_idx(SESS_B));
}

/* An update the hub accepts: SUBSCRIBER_PRIORITY v. */
static void mtuo_prio(u8 v) {
  moqctl_params p = mtst_params_u8(MOQCTL_PARAM_SUBSCRIBER_PRIORITY, v);
  mtup_update(SESS_B, MTRQ_S1, &p);
}

/* An update that fails: FORWARD 0 -> 1 whose blob send is refused
 * (INTERNAL_ERROR, moqtrun_upd_apply). */
static void mtuo_fail(void) {
  moqctl_params p1  = mtst_params_u8(MOQCTL_PARAM_FORWARD, 1);
  g_send_uni_fail_n = 1;
  mtup_update(SESS_B, MTRQ_S1, &p1);
}

static u64 mtuo_pending(void) {
  return moqtrun_req_find(&mtst_hub, SESS_B, MTRQ_S1)->pending_updates;
}

/* ===================== order ===================== */

/* 9.5: immediate updates are applied and answered one by one, in the
 * order received; the state is the last one's. */
static void test_moqtrun_d23uo_immediate_in_order(void) {
  u64 t[4];
  mtuo_sub();
  mtuo_prio(1);
  mtuo_prio(2);
  mtuo_prio(3);
  CHECK(mtuo_replies(MTRQ_S1, t, 4) == 3);
  CHECK(t[0] == MOQCTL_T_REQUEST_OK && t[1] == MOQCTL_T_REQUEST_OK);
  CHECK(t[2] == MOQCTL_T_REQUEST_OK);
  CHECK(mtuo_s() && mtuo_s()->priority == 3);
}

/* 9.5: the hub does not coalesce; two updates get two OKs and leave the
 * state one update carrying both values would. */
static void test_moqtrun_d23uo_coalesce_equals_sequential(void) {
  moqctl_params both = mtst_params_u8(MOQCTL_PARAM_FORWARD, 1);
  both.items[1] = mtst_params_u8(MOQCTL_PARAM_SUBSCRIBER_PRIORITY, 5).items[0];
  both.n        = 2;
  mtuo_sub();
  mtup_update(SESS_B, MTRQ_S1, &both);
  u8 once_fwd = mtuo_s()->forward_off, once_pri = mtuo_s()->priority;
  mtuo_sub();
  mtuo_prio(5);
  moqctl_params p1 = mtst_params_u8(MOQCTL_PARAM_FORWARD, 1);
  mtup_update(SESS_B, MTRQ_S1, &p1);
  CHECK(mtuo_n() == 2);
  CHECK(mtuo_s()->forward_off == once_fwd && mtuo_s()->priority == once_pri);
}

/* A reply the transport refuses stays queued and goes out at the next
 * tick ahead of the reply to the update after it. */
static void test_moqtrun_d23uo_refused_reply_keeps_order(void) {
  u64 t[4];
  mtuo_sub();
  g_stream_send_ok_n = 0;
  mtuo_prio(1);
  mtuo_fail();
  CHECK(mtuo_n() == 0);
  g_stream_send_ok_n = -1;
  wired_moqt_tick(&mtst_hub, 1);
  CHECK(mtuo_replies(MTRQ_S1, t, 4) == 2);
  CHECK(t[0] == MOQCTL_T_REQUEST_OK && t[1] == MOQCTL_T_REQUEST_ERROR);
}

/* ===================== a failure ends the request ===================== */

/* draft-23 9.5.1: OK for update 1, one REQUEST_ERROR for update 2, and
 * update 3 -- read after the request ended -- gets nothing. */
static void test_moqtrun_d23uo_error_covers_queued(void) {
  u64 t[4];
  mtuo_sub();
  mtuo_prio(1);
  mtuo_fail();
  mtuo_prio(3);
  CHECK(mtuo_replies(MTRQ_S1, t, 4) == 2);
  CHECK(t[0] == MOQCTL_T_REQUEST_OK && t[1] == MOQCTL_T_REQUEST_ERROR);
  CHECK(mtuo_s() == 0);
  CHECK(mtuo_pending() == 1); /* update 3: dropped, never credited back */
}

/* draft-23 9.5.1: an update arriving after a failure ended the request
 * is discarded without a reply; earlier drafts still answer it. */
static void test_moqtrun_d23uo_after_end_no_reply(void) {
  mtuo_sub();
  mtuo_fail();
  CHECK(mtuo_n() == 1);
  mtuo_prio(2);
  CHECK(mtuo_n() == 1);
}

static void mtuo_after_end_answered_d22(void) {
  mtuo_sub();
  mtuo_fail();
  mtuo_prio(2);
  CHECK(mtuo_n() == 2);
}

/* 9.5.1: a failed update of a subscription ends it with PUBLISH_DONE
 * UPDATE_FAILED. */
static void test_moqtrun_d23uo_failed_update_publish_done(void) {
  u64 count;
  mtuo_sub();
  mtuo_fail();
  CHECK(mtdr_done_on(MTRQ_S1, &count) == MOQCTL_DONE_UPDATE_FAILED);
}

/* ===================== credit (9.1.7) ===================== */

/* One past MAX_REQUEST_UPDATES unanswered closes the session
 * TOO_MANY_REQUEST_UPDATES; MAX itself does not. */
static void test_moqtrun_d23uo_over_credit_closes(void) {
  mtuo_sub();
  g_stream_send_ok_n = 0;
  for (u8 i = 0; i < WIRED_MOQTRUN_MAX_REQ_UPDATES; i++) {
    mtuo_prio(i);
  }
  CHECK(mtup_close_count(WIRED_MOQTRUN_CLOSE_TOO_MANY_REQUEST_UPDATES) == 0);
  mtuo_prio(9);
  CHECK(mtup_close_count(WIRED_MOQTRUN_CLOSE_TOO_MANY_REQUEST_UPDATES) == 1);
  g_stream_send_ok_n = -1;
}

/* draft-23 9.1.7: updates dropped after the request ended stay
 * unanswered, so MAX of them plus one more closes the session. */
static void test_moqtrun_d23uo_over_credit_after_end(void) {
  mtuo_sub();
  g_stream_send_ok_n = 0; /* the REQUEST_ERROR is not out yet */
  mtuo_fail();
  for (u8 i = 1; i < WIRED_MOQTRUN_MAX_REQ_UPDATES; i++) {
    mtuo_prio(i);
  }
  CHECK(mtup_close_count(WIRED_MOQTRUN_CLOSE_TOO_MANY_REQUEST_UPDATES) == 0);
  mtuo_prio(9);
  CHECK(mtup_close_count(WIRED_MOQTRUN_CLOSE_TOO_MANY_REQUEST_UPDATES) == 1);
  g_stream_send_ok_n = -1;
}

/* draft-23 9.1.7: flushing the REQUEST_ERROR credits back the failed
 * update only; the dropped ones stay unanswered, so the second update
 * past MAX closes the session. */
static void test_moqtrun_d23uo_flush_keeps_dropped_outstanding(void) {
  mtuo_sub();
  g_stream_send_ok_n = 0;
  mtuo_fail();
  for (u8 i = 1; i < WIRED_MOQTRUN_MAX_REQ_UPDATES; i++) {
    mtuo_prio(i);
  }
  g_stream_send_ok_n = -1;
  wired_moqt_tick(&mtst_hub, 1);
  CHECK(mtuo_pending() == WIRED_MOQTRUN_MAX_REQ_UPDATES - 1);
  mtuo_prio(8);
  CHECK(mtup_close_count(WIRED_MOQTRUN_CLOSE_TOO_MANY_REQUEST_UPDATES) == 0);
  mtuo_prio(9);
  CHECK(mtup_close_count(WIRED_MOQTRUN_CLOSE_TOO_MANY_REQUEST_UPDATES) == 1);
}

/* A peer that never has more than MAX updates unanswered -- whether the
 * replies flush at once, are held back, or the request ended -- is never
 * closed for credit. A pseudo-random schedule from seed x of sends,
 * refused flushes and one failure. */
static void mtuo_honest_peer(u32 x) {
  u64 sent = 0; /* the peer's own count: sent - replies read = outstanding */
  mtuo_sub();
  for (usz round = 0; round < 64; round++) {
    x                  = x * 1103515245u + 12345u;
    g_stream_send_ok_n = (x >> 16) & 1 ? -1 : 0;
    if (sent - mtuo_n() < WIRED_MOQTRUN_MAX_REQ_UPDATES) {
      round == 20 ? mtuo_fail() : mtuo_prio((u8)round);
      sent++;
    }
    wired_moqt_tick(&mtst_hub, round);
  }
  g_stream_send_ok_n = -1;
  CHECK(mtup_close_count(WIRED_MOQTRUN_CLOSE_TOO_MANY_REQUEST_UPDATES) == 0);
}

/* Seeds the schedules are drawn from. */
static const u32 MTUO_SEEDS[] = {12345, 1, 777, 2024, 31337, 65521};

static void test_moqtrun_d23uo_honest_peer_never_closed(void) {
  for (usz i = 0; i < sizeof MTUO_SEEDS / sizeof MTUO_SEEDS[0]; i++) {
    mtuo_honest_peer(MTUO_SEEDS[i]);
  }
}

/* After the credit close neither the update past the credit nor a later
 * one is applied or answered, and the MAX replies still queued when the
 * session closed are dropped: nothing more goes out on the stream. */
static void test_moqtrun_d23uo_nothing_after_close(void) {
  mtuo_sub();
  g_stream_send_ok_n = 0;
  for (u8 i = 1; i <= WIRED_MOQTRUN_MAX_REQ_UPDATES; i++) {
    mtuo_prio(i);
  }
  mtuo_prio(8); /* one past the credit */
  CHECK(mtup_close_count(WIRED_MOQTRUN_CLOSE_TOO_MANY_REQUEST_UPDATES) == 1);
  g_stream_send_ok_n = -1;
  mtuo_prio(9);
  wired_moqt_tick(&mtst_hub, 1);
  CHECK(mtuo_s() && mtuo_s()->priority == WIRED_MOQTRUN_MAX_REQ_UPDATES);
  CHECK(mtuo_n() == 0);
}

/* ===================== kinds of failure ===================== */

/* Reply count on request stream sid. */
static usz mtuo_n_on(u64 sid) {
  u64 t[16];
  return mtuo_replies(sid, t, 16);
}

/* A reply held back on B's control stream (a PUBLISH_NAMESPACE there is
 * NOT_SUPPORTED, 6.2) goes out with B's next control message -- here a
 * REQUEST_UPDATE, which answers nothing there (9.5) -- unless the session
 * closed meanwhile: then it is dropped too. */
static usz mtuo_ctl_reply_after(int close) {
  mtuo_sub();
  u64 cb             = moqtrun_find_by_wt(&mtst_hub, SESS_B)->control_stream_id;
  g_stream_send_ok_n = 0;
  mtns_pub(SESS_B, cb, "chat/room2");
  for (u8 i = 0; close && i <= WIRED_MOQTRUN_MAX_REQ_UPDATES; i++) {
    mtuo_prio(i); /* the last one is past the credit */
  }
  CHECK(
      mtup_close_count(WIRED_MOQTRUN_CLOSE_TOO_MANY_REQUEST_UPDATES) ==
      (usz)close);
  g_stream_send_ok_n = -1;
  wired_moqt_tick(&mtst_hub, 1);
  mtup_update(SESS_B, cb, &(moqctl_params){0});
  return mtuo_n_on(cb);
}

static void test_moqtrun_d23uo_ctl_reply_dropped_on_close(void) {
  CHECK(mtuo_ctl_reply_after(0) == 1);
  CHECK(mtuo_ctl_reply_after(1) == 0);
}

/* draft-23 9.5.1: a refused switch (INVALID_SWITCH) ends the request
 * like any failed update -- PUBLISH_DONE UPDATE_FAILED, the subscription
 * gone, a later update unanswered. Earlier drafts keep the subscription
 * (test_moqtrun_switch_update). */
static void test_moqtrun_d23uo_invalid_switch_ends(void) {
  static const u8 bad[] = {0x08, 0x01, 0x24, 0x03, 0x28, 0x01, 0x80};
  u64             count;
  moqctl_params   p0 = mtst_params_u8(MOQCTL_PARAM_FORWARD, 0);
  moqctl_params   pr = mtst_params_u8(MOQCTL_PARAM_SUBSCRIBER_PRIORITY, 1);
  moqctl_ftn      lo = mtsw_ftn("lo");
  mtsw_setup();
  mtst_subscribe_p(SESS_B, MTRQ_S2, &lo, MTSW_RID_LO, &p0);
  mtrq_raw(SESS_B, MTRQ_S2, MOQTSTAT_T_REQUEST_UPDATE, bad, sizeof bad);
  CHECK(mtrq_err_on(MTRQ_S2) == MOQCTL_ERR_INVALID_SWITCH);
  CHECK(mtsw_lo() == 0);
  CHECK(mtdr_done_on(MTRQ_S2, &count) == MOQCTL_DONE_UPDATE_FAILED);
  mtup_update(SESS_B, MTRQ_S2, &pr);
  CHECK(mtuo_n_on(MTRQ_S2) == 1);
}

/* draft-23 9.19.15: a FILL_PARAMETERS update that would open one fill
 * too many is EXCESSIVE_LOAD and ends the subscription (PUBLISH_DONE
 * UPDATE_FAILED); earlier drafts answer INTERNAL_ERROR
 * (test_moqtrun_fillfix_full_update_refused). */
static void test_moqtrun_d23uo_fill_excessive_load_ends(void) {
  moqfetch_fill fill = {0};
  u64           count;
  mffx_three_groups();
  moqtrun_find_by_wt(&mtst_hub, SESS_B)->ver = MOQVER_D19;
  mffx_fill_tables(); /* its FETCHes use B's pre-draft-22 layout */
  mfill_subscribe_req(0);
  moqtrun_find_by_wt(&mtst_hub, SESS_B)->ver = g_moqtrun_test_ver;
  moqctl_params p                            = mfill_params(&fill, 0);
  p.items[0].enc = MOQCTL_PENC_FILL23; /* count, no Length (9.19.15) */
  mtup_update(SESS_B, MTRQ_S1, &p);
  CHECK(mtrq_err_on(MTRQ_S1) == MOQCTL_ERR_EXCESSIVE_LOAD);
  CHECK(mtst_sub(SESS_A, SESS_B) == 0);
  CHECK(mtdr_done_on(MTRQ_S1, &count) == MOQCTL_DONE_UPDATE_FAILED);
}

/* A's own PUBLISH on MTDN_PUB, which B subscribes (moqtrun_done_test.c),
 * gets a refused update (an inverted LOCATION_FILTER is INVALID_RANGE)
 * and then an acceptable one. */
static usz mtuo_pub_refused_then_update(int done) {
  moqctl_params bad =
      mt22_filter(1, mt22_rl(MOQCTL_RSK_ABS, 5, 5, MOQCTL_REK_OBJ, 5, 1));
  mtdn_setup();
  if (done) {
    mtdn_done(MOQCTL_DONE_TRACK_ENDED, 0); /* the track is withdrawn */
  }
  usz n0 = mtuo_n_on(MTDN_PUB); /* a draft-22 PUBLISH is answered REQUEST_OK */
  mtup_update(SESS_A, MTDN_PUB, &bad);
  CHECK(mtup_err_code(MTDN_PUB) == MOQCTL_ERR_INVALID_RANGE);
  mtup_update(SESS_A, MTDN_PUB, &(moqctl_params){0});
  return mtuo_n_on(MTDN_PUB) - n0;
}

/* Data streams the hub opened (send_uni / open_uni). */
static usz mtuo_unis(void) {
  return moqtrun_test_count_kind(4) + moqtrun_test_count_kind(5);
}

/* draft-23 9.5.1: refusing an update of the peer's own PUBLISH ends the
 * request too: the next update gets no reply, the track is withdrawn --
 * B gets PUBLISH_DONE, A's later objects are not relayed -- and the hub
 * FINs its side of the PUBLISH stream once its REQUEST_ERROR is out
 * (6.4.2.2). */
static void test_moqtrun_d23uo_publish_update_refused_ends(void) {
  u64 count;
  CHECK(mtuo_pub_refused_then_update(0) == 1);
  CHECK(mtdr_done_on(MTRQ_S1, &count) == MOQCTL_DONE_TRACK_ENDED);
  CHECK(mtdn_published() == 0);
  CHECK(mtrq_fin_on(MTDN_PUB) == 1);
  usz n = mtuo_unis();
  mtdn_group(2002, 1);
  CHECK(mtuo_unis() == n);
}

/* draft-23 9.5.1: after A's own PUBLISH_DONE withdrew the track (its
 * stream not FINed yet) a refused update still ends the request, with no
 * track left to withdraw: the next update gets no reply. */
static void test_moqtrun_d23uo_publish_update_refused_after_done(void) {
  CHECK(mtuo_pub_refused_then_update(1) == 1);
}

/* draft-22: the request stays, the next update is REQUEST_OK and the
 * track is still published. */
static void mtuo_publish_refused_keeps_d22(void) {
  CHECK(mtuo_pub_refused_then_update(0) == 2);
  CHECK(mtdn_published() == 1);
}

/* A TRACK_NAMESPACE_PREFIX update the hub cannot store (one field past
 * WIRED_MOQTRUN_MAX_NS) is refused and leaves the request's prefix "chat"
 * as it was -- no half-written prefix (9.5). On draft-23 the request has
 * ended, so a later update is not answered. */
static void test_moqtrun_d23uo_failed_prefix_keeps_old(void) {
  static char big[WIRED_MOQTRUN_MAX_NS + 8];
  u8          want[16];
  usz         n    = 0;
  moqctl_ns   chat = mtns_ns("chat");
  bytes_memset(big, 'x', sizeof big - 1);
  CHECK(moqctl_ns_put(wired_mspan_of(want, sizeof want), &n, &chat));
  mtns_init();
  mtns_sub(SESS_B, MTRQ_S1, "chat");
  usz           n0 = mtuo_n_on(MTRQ_S1); /* its own REQUEST_OK */
  moqctl_params p  = mtup_ns_param(big);
  mtup_update(SESS_B, MTRQ_S1, &p);
  CHECK(mtup_err_code(MTRQ_S1) == MOQCTL_ERR_INTERNAL_ERROR);
  wired_moqtrun_req* q = moqtrun_req_find(&mtst_hub, SESS_B, MTRQ_S1);
  CHECK(q && q->ns_len == n && moqtrun_bytes_eq(q->ns, want, n));
  mtup_update(SESS_B, MTRQ_S1, &(moqctl_params){0});
  CHECK(
      mtuo_n_on(MTRQ_S1) - n0 ==
      ((moqver_caps(g_moqtrun_test_ver) & MOQVER_CAP_UPD_ERR_ENDS) ? 1 : 2));
}

/* ===================== never coalesced (9.19.15, 9.19.20) ============ */

/* A FILL_PARAMETERS update and the plain update after it get one reply
 * each. */
static void test_moqtrun_d23uo_fill_not_coalesced(void) {
  moqctl_params base = mffx_sub_filter(MOQCTL_RSK_ABS, 2);
  mffx_three_groups();
  mfill_subscribe_req(&base);
  usz           n0  = mtuo_n_on(MTRQ_S1);
  moqctl_params upd = mffx_no_lf(0);
  mtup_update(SESS_B, MTRQ_S1, &upd);
  mtuo_prio(4);
  CHECK(mtuo_n_on(MTRQ_S1) - n0 == 2);
}

/* A TRACK_NAMESPACE_PREFIX update and the plain update after it get one
 * reply each. */
static void test_moqtrun_d23uo_prefix_not_coalesced(void) {
  mtns_init();
  mtns_sub(SESS_B, MTRQ_S1, "chat");
  usz           n0 = mtuo_n_on(MTRQ_S1);
  moqctl_params p  = mtup_ns_param("video");
  mtup_update(SESS_B, MTRQ_S1, &p);
  mtup_update(SESS_B, MTRQ_S1, &(moqctl_params){0});
  CHECK(mtuo_n_on(MTRQ_S1) - n0 == 2);
}

/* ============ pipelined in one delivery (9.5, synchronous) ============ */

/* Updates a then b on MTRQ_S1, both in one delivery: the hub reads both
 * before it flushes anything. */
static void mtuo_two(const moqctl_params* a, const moqctl_params* b) {
  static moqtstat_update    m[2];
  u8                        buf[2 * MTST_MSG_MAX];
  usz                       n     = 0;
  const moqctl_params*      ps[2] = {a, b};
  const wired_moqtrun_peer* pb    = moqtrun_find_by_wt(&mtst_hub, SESS_B);
  g_mtst_send_ver                 = pb->ver;
  for (usz i = 0; i < 2; i++) {
    m[i].request_id = mtst_rid += 4;
    m[i].params     = *ps[i];
    mtst_params_for(SESS_B, &m[i].params);
    n += moqtrun_envelope_put(
        MOQVER_D22, wired_mspan_of(buf + n, sizeof buf - n),
        MOQTSTAT_T_REQUEST_UPDATE, mtup_enc_update, &m[i]);
  }
  mt_feed(&mtst_hub, SESS_B, MTRQ_S1, wired_span_of(buf, n), 0);
}

/* 9.5: two updates read together are answered one OK each, in received
 * order, and the state is both applied in order. The hub decides each on
 * receipt (no upstream wait), so the second never overtakes the first. */
static void test_moqtrun_d23uo_pipelined_in_order(void) {
  u64           t[4];
  moqctl_params on = mtst_params_u8(MOQCTL_PARAM_FORWARD, 1);
  moqctl_params pr = mtst_params_u8(MOQCTL_PARAM_SUBSCRIBER_PRIORITY, 2);
  mtuo_sub();
  mtuo_two(&on, &pr);
  CHECK(mtuo_replies(MTRQ_S1, t, 4) == 2);
  CHECK(t[0] == MOQCTL_T_REQUEST_OK && t[1] == MOQCTL_T_REQUEST_OK);
  CHECK(mtuo_s() && !mtuo_s()->forward_off && mtuo_s()->priority == 2);
}

/* draft-23 9.5.1: of two updates read together, a failed first one gets
 * the one REQUEST_ERROR and the second is dropped, never applied. */
static void test_moqtrun_d23uo_pipelined_failure_drops_second(void) {
  u64           t[4];
  moqctl_params on = mtst_params_u8(MOQCTL_PARAM_FORWARD, 1);
  moqctl_params pr = mtst_params_u8(MOQCTL_PARAM_SUBSCRIBER_PRIORITY, 2);
  mtuo_sub();
  g_send_uni_fail_n = 1; /* the FORWARD 0 -> 1 blob send is refused */
  mtuo_two(&on, &pr);
  CHECK(mtuo_replies(MTRQ_S1, t, 4) == 1);
  CHECK(t[0] == MOQCTL_T_REQUEST_ERROR);
  CHECK(mtuo_s() == 0);
}

/* draft-23 9.1.7: one REQUEST_ERROR answers one update, so after it is
 * flushed the update dropped behind it stays outstanding: MAX - 1 more
 * are dropped without a close, the next one closes. */
static void test_moqtrun_d23uo_error_credits_only_answered(void) {
  moqctl_params on = mtst_params_u8(MOQCTL_PARAM_FORWARD, 1);
  moqctl_params pr = mtst_params_u8(MOQCTL_PARAM_SUBSCRIBER_PRIORITY, 2);
  mtuo_sub();
  g_send_uni_fail_n = 1;
  mtuo_two(&on, &pr);
  CHECK(mtuo_pending() == 1);
  for (u8 i = 1; i < WIRED_MOQTRUN_MAX_REQ_UPDATES; i++) {
    mtuo_prio(i);
  }
  CHECK(mtup_close_count(WIRED_MOQTRUN_CLOSE_TOO_MANY_REQUEST_UPDATES) == 0);
  mtuo_prio(9);
  CHECK(mtup_close_count(WIRED_MOQTRUN_CLOSE_TOO_MANY_REQUEST_UPDATES) == 1);
}

/* draft-23 9.5: whatever mix of accepted, failed and back-pressured
 * updates, once the transport drains every update sent has one reply or
 * was dropped after the request ended (outstanding for good) -- never
 * neither. A pseudo-random schedule from seed x within the credit. */
static u64 mtuo_every_resolved(u32 x, int fails) {
  u64 sent = 0, dropped = 0; /* dropped: sent after the first failure */
  int failed = 0;
  mtuo_sub();
  for (usz round = 0; round < 40; round++) {
    x                  = x * 1103515245u + 12345u;
    g_stream_send_ok_n = (x >> 16) & 1 ? -1 : 0;
    if (sent - mtuo_n() < WIRED_MOQTRUN_MAX_REQ_UPDATES) {
      int fail = fails && (x >> 20) % 9 == 0;
      dropped += failed;
      failed |= fail;
      fail ? mtuo_fail() : mtuo_prio((u8)round);
      sent++;
    }
    wired_moqt_tick(&mtst_hub, round);
  }
  g_stream_send_ok_n = -1;
  wired_moqt_tick(&mtst_hub, 99);
  CHECK(mtup_close_count(WIRED_MOQTRUN_CLOSE_TOO_MANY_REQUEST_UPDATES) == 0);
  CHECK(mtuo_pending() == dropped);
  CHECK(mtuo_n() + dropped == sent);
  return dropped;
}

/* Each seed's schedule with its failures, then the same with none: then
 * nothing is dropped, every update sent is answered. */
static void test_moqtrun_d23uo_every_update_resolved(void) {
  for (usz i = 0; i < sizeof MTUO_SEEDS / sizeof MTUO_SEEDS[0]; i++) {
    CHECK(mtuo_every_resolved(MTUO_SEEDS[i], 1) > 0);
    CHECK(mtuo_every_resolved(MTUO_SEEDS[i], 0) == 0);
  }
}

/* 9.5: the hub sent the SUBSCRIBE, so the publisher A is its receiver;
 * a REQUEST_UPDATE from A on that stream closes the session
 * UNEXPECTED_MESSAGE and is not answered. */
static void mtuo_wrong_direction(void) {
  moqctl_params p = mtst_params_u8(MOQCTL_PARAM_FORWARD, 0);
  mnsx_relay();
  mtns_pub(SESS_A, MTRQ_S1, "a");
  mnsx_dsub(MTRQ_S1);
  u64 up = (u64)mups_up_sid();
  usz n0 = mtuo_n_on(up);
  mtup_update(SESS_A, up, &p);
  CHECK(mtrq_closes_cc(WIRED_MOQTRUN_CLOSE_UNEXPECTED_MESSAGE) == 1);
  CHECK(mtuo_n_on(up) == n0);
}

/* draft-18 10.9 has no such sentence: the session stays up. */
static void mtuo_wrong_direction_kept_d18(void) {
  moqctl_params p = mtst_params_u8(MOQCTL_PARAM_FORWARD, 0);
  mnsx_relay();
  mtns_pub(SESS_A, MTRQ_S1, "a");
  mnsx_dsub(MTRQ_S1);
  CHECK(mups_up_sid() >= 0);
  mtup_update(SESS_A, (u64)mups_up_sid(), &p);
  CHECK(moqtrun_test_count_kind(11) == 0);
}

static void test_moqtrun_d23uo_wrong_direction_unexpected(void) {
  moqtrun_test_vers(MOQVER_CAP_UPDATE_STRAY_CLOSE, 0, mtuo_wrong_direction);
  moqtrun_test_vers(
      0, MOQVER_CAP_UPDATE_STRAY_CLOSE, mtuo_wrong_direction_kept_d18);
}

/* 9.5: the hub sent this FETCH upstream to A, so A's REQUEST_UPDATE on
 * its stream closes the session UNEXPECTED_MESSAGE (closes: 1); draft-18
 * keeps the session (closes: 0). */
static void mtuo_upfetch_update(usz closes) {
  moqfetch_req  m = {0};
  moqctl_params p = mtst_params_u8(MOQCTL_PARAM_SUBSCRIBER_PRIORITY, 1);
  mupf_init();
  mupf_cache_group(3, 2);
  mupf_fetch(mupf_rl(1, 0, 4, 1), 0);
  i64 sid = mupf_up(SESS_A, 0, &m);
  CHECK(sid >= 0);
  mtup_update(SESS_A, (u64)sid, &p);
  CHECK(mtrq_closes_cc(WIRED_MOQTRUN_CLOSE_UNEXPECTED_MESSAGE) == closes);
}

static void mtuo_upfetch_update_closes(void) { mtuo_upfetch_update(1); }

static void mtuo_upfetch_update_kept_d18(void) { mtuo_upfetch_update(0); }

static void test_moqtrun_d23uo_upfetch_update_unexpected(void) {
  moqtrun_test_vers(
      MOQVER_CAP_UPDATE_STRAY_CLOSE, 0, mtuo_upfetch_update_closes);
  moqtrun_test_vers(
      0, MOQVER_CAP_UPDATE_STRAY_CLOSE, mtuo_upfetch_update_kept_d18);
}

/* A answers the hub's FETCH for the whole range asked: a REQUEST_OK in
 * draft-23 (9.3), a FETCH_OK before. */
static void mtuo_upf_answered(i64 sid) {
  if (moqver_caps(mtst_ver(SESS_A)) & MOQVER_CAP_FETCH_REQUEST_OK) {
    mupf23_up_ok(SESS_A, sid, 0, 0, 0, wired_span_of(0, 0));
    return;
  }
  mupf_up_ok(sid, 2, MOQFETCH_OBJ_GROUP_END);
}

/* 9.5: the hub's FETCH stream stays a request stream after its leg
 * ended -- end 0: the response done (the hub FINs), 1: a REQUEST_ERROR,
 * 2: cancelled (the hub resets it); its stream id. */
static u64 mtuo_upf_ended(int end) {
  static const moqctl_request_error e   = {.error_code = 1};
  moqfetch_req                      m   = {0};
  i64                               sid = mupf_span_setup(&m);
  if (end == 0) {
    mtuo_upf_answered(sid);
    mupf_send(1);
  }
  if (end == 1) {
    mupf_up_err(SESS_A, sid, &e);
  }
  if (end == 2) {
    wired_moqt_on_stream_reset(&mtst_hub, SESS_A, MUPF_DATA_SID, 1, 0);
  }
  CHECK(mupf_log_is(SESS_A, (u64)sid, end == 2 ? "RST1|STOP1|" : "FIN|"));
  return (u64)sid;
}

/* A's REQUEST_UPDATE on the ended stream closes the session
 * UNEXPECTED_MESSAGE (closes: 1; draft-18 keeps it, closes: 0). */
static void mtuo_upf_ended_update(usz closes) {
  moqctl_params p = mtst_params_u8(MOQCTL_PARAM_SUBSCRIBER_PRIORITY, 1);
  for (int end = 0; end < 3; end++) {
    u64 sid = mtuo_upf_ended(end);
    mtup_update(SESS_A, sid, &p);
    CHECK(mtrq_closes_cc(WIRED_MOQTRUN_CLOSE_UNEXPECTED_MESSAGE) == closes);
  }
}

static void mtuo_upf_ended_closes(void) { mtuo_upf_ended_update(1); }

static void mtuo_upf_ended_kept_d18(void) { mtuo_upf_ended_update(0); }

/* Other bytes on it are dropped, never read as a uni stream: a stream
 * type SETUP (0x2F00, 3.4) there must not adopt it as A's control
 * stream. The hub sends nothing. */
static void mtuo_upf_ended_junk(void) {
  static const u8 junk[] = {0xAF, 0x00, 0x00, 0x00}; /* 0x2F00 */
  for (int end = 0; end < 3; end++) {
    u64 sid = mtuo_upf_ended(end);
    usz n0  = g_n_calls;
    mt_feed(&mtst_hub, SESS_A, sid, wired_span_of(junk, sizeof junk), 0);
    CHECK(g_n_calls == n0);
    CHECK(moqtrun_find_by_wt(&mtst_hub, SESS_A)->peer_ctl_stream_id != sid);
  }
}

static void test_moqtrun_d23uo_upfetch_ended_update(void) {
  moqtrun_test_vers(MOQVER_CAP_UPDATE_STRAY_CLOSE, 0, mtuo_upf_ended_closes);
  moqtrun_test_vers(0, MOQVER_CAP_UPDATE_STRAY_CLOSE, mtuo_upf_ended_kept_d18);
  moqtrun_test_allver(mtuo_upf_ended_junk);
}

/* The same for the hub's upstream SUBSCRIBE once A ended it -- end 0:
 * PUBLISH_DONE after SUBSCRIBE_OK, 1: a REQUEST_ERROR. */
static u64 mtuo_ups_ended(int end) {
  static const moqctl_request_error e = {.error_code = 1};
  mnsx_relay();
  mtns_pub(SESS_A, MTRQ_S1, "a");
  mnsx_dsub(MTRQ_S1);
  u64 up = (u64)mups_up_sid();
  if (end == 0) {
    mups_ok(up);
    mups_done(up, 0);
  }
  if (end == 1) {
    mupf_up_err(SESS_A, (i64)up, &e);
  }
  CHECK(mups_used() == 0);
  return up;
}

static void mtuo_ups_ended_update(usz closes) {
  moqctl_params p = mtst_params_u8(MOQCTL_PARAM_FORWARD, 0);
  for (int end = 0; end < 2; end++) {
    mtup_update(SESS_A, mtuo_ups_ended(end), &p);
    CHECK(mtrq_closes_cc(WIRED_MOQTRUN_CLOSE_UNEXPECTED_MESSAGE) == closes);
  }
}

static void mtuo_ups_ended_closes(void) { mtuo_ups_ended_update(1); }

static void mtuo_ups_ended_kept_d18(void) { mtuo_ups_ended_update(0); }

static void test_moqtrun_d23uo_upsub_ended_update(void) {
  moqtrun_test_vers(MOQVER_CAP_UPDATE_STRAY_CLOSE, 0, mtuo_ups_ended_closes);
  moqtrun_test_vers(0, MOQVER_CAP_UPDATE_STRAY_CLOSE, mtuo_ups_ended_kept_d18);
}

/* ===================== registration ===================== */

static void mtuo_all(void) {
  test_moqtrun_d23uo_pipelined_in_order();
  test_moqtrun_d23uo_immediate_in_order();
  test_moqtrun_d23uo_coalesce_equals_sequential();
  test_moqtrun_d23uo_refused_reply_keeps_order();
  test_moqtrun_d23uo_failed_update_publish_done();
  test_moqtrun_d23uo_failed_prefix_keeps_old();
  test_moqtrun_d23uo_fill_not_coalesced();
  test_moqtrun_d23uo_prefix_not_coalesced();
}

static void mtuo_d23(void) {
  test_moqtrun_d23uo_pipelined_failure_drops_second();
  test_moqtrun_d23uo_every_update_resolved();
  test_moqtrun_d23uo_error_credits_only_answered();
  test_moqtrun_d23uo_error_covers_queued();
  test_moqtrun_d23uo_after_end_no_reply();
  test_moqtrun_d23uo_over_credit_after_end();
  test_moqtrun_d23uo_flush_keeps_dropped_outstanding();
  test_moqtrun_d23uo_invalid_switch_ends();
  test_moqtrun_d23uo_fill_excessive_load_ends();
  test_moqtrun_d23uo_publish_update_refused_ends();
  test_moqtrun_d23uo_publish_update_refused_after_done();
}

static void mtuo_credit(void) {
  test_moqtrun_d23uo_over_credit_closes();
  test_moqtrun_d23uo_honest_peer_never_closed();
  test_moqtrun_d23uo_nothing_after_close();
  test_moqtrun_d23uo_ctl_reply_dropped_on_close();
}

void test_moqtrun_d23uo(void) {
  moqtrun_test_allver(mtuo_all);
  moqtrun_test_vers(MOQVER_CAP_UPD_ERR_ENDS, 0, mtuo_d23);
  moqtrun_test_vers(0, MOQVER_CAP_UPD_ERR_ENDS, mtuo_after_end_answered_d22);
  moqtrun_test_vers(
      MOQVER_CAP_LOCFILTER_TYPED, MOQVER_CAP_UPD_ERR_ENDS,
      mtuo_publish_refused_keeps_d22);
  moqtrun_test_vers(MOQVER_CAP_MAX_REQUEST_UPDATES, 0, mtuo_credit);
  test_moqtrun_d23uo_wrong_direction_unexpected();
  test_moqtrun_d23uo_upfetch_update_unexpected();
  test_moqtrun_d23uo_upfetch_ended_update();
  test_moqtrun_d23uo_upsub_ended_update();
}
