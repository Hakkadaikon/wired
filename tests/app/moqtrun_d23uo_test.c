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
  u64 t[16];
  return mtuo_replies(MTRQ_S1, t, 16);
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
  CHECK(t[0] == MOQCTL_T_REQUEST_OK && t[2] == MOQCTL_T_REQUEST_OK);
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
 * closed for credit. A fixed pseudo-random schedule of sends, refused
 * flushes and one failure. */
static void test_moqtrun_d23uo_honest_peer_never_closed(void) {
  u32 x   = 12345;
  u64 out = 0; /* the peer's own count: sent, reply not read */
  mtuo_sub();
  for (usz round = 0; round < 64; round++) {
    x                  = x * 1103515245u + 12345u;
    g_stream_send_ok_n = (x >> 16) & 1 ? -1 : 0;
    if (out < WIRED_MOQTRUN_MAX_REQ_UPDATES) {
      round == 20 ? mtuo_fail() : mtuo_prio((u8)round);
      out++;
    }
    wired_moqt_tick(&mtst_hub, round);
    out = g_stream_send_ok_n ? mtuo_pending() : out;
  }
  g_stream_send_ok_n = -1;
  CHECK(mtup_close_count(WIRED_MOQTRUN_CLOSE_TOO_MANY_REQUEST_UPDATES) == 0);
}

/* After the credit close neither the update past the credit nor a later
 * one is applied or answered: only the MAX replies queued before it go. */
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
  CHECK(mtuo_n() <= WIRED_MOQTRUN_MAX_REQ_UPDATES);
}

/* ===================== registration ===================== */

static void mtuo_all(void) {
  test_moqtrun_d23uo_immediate_in_order();
  test_moqtrun_d23uo_coalesce_equals_sequential();
  test_moqtrun_d23uo_refused_reply_keeps_order();
  test_moqtrun_d23uo_failed_update_publish_done();
}

static void mtuo_d23(void) {
  test_moqtrun_d23uo_error_covers_queued();
  test_moqtrun_d23uo_after_end_no_reply();
  test_moqtrun_d23uo_over_credit_after_end();
  test_moqtrun_d23uo_flush_keeps_dropped_outstanding();
}

static void mtuo_credit(void) {
  test_moqtrun_d23uo_over_credit_closes();
  test_moqtrun_d23uo_honest_peer_never_closed();
  test_moqtrun_d23uo_nothing_after_close();
}

void test_moqtrun_d23uo(void) {
  moqtrun_test_allver(mtuo_all);
  moqtrun_test_vers(MOQVER_CAP_UPD_ERR_ENDS, 0, mtuo_d23);
  moqtrun_test_vers(0, MOQVER_CAP_UPD_ERR_ENDS, mtuo_after_end_answered_d22);
  moqtrun_test_vers(MOQVER_CAP_MAX_REQUEST_UPDATES, 0, mtuo_credit);
}
