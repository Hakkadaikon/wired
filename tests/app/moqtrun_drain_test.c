/* Hub stream priority (draft-ietf-moq-transport-19 7), GOAWAY / session
 * drain (3.6, 10.4) and PUBLISH_DONE (10.11). Shares the recording io
 * stubs (moqtrun_test.c) and the subscription / request-stream fixtures
 * (moqtrun_sub_test.c, moqtrun_upd_test.c) of the same unity TU. */

/* ===================== priority (7) ===================== */

/* io.stream_priority stub: kind 13, the urgency rides the fin field. */
static int mtdr_prio(wired_wt_session* s, u64 stream_id, u8 urgency) {
  moqtrun_test_record(13, s, stream_id, urgency, wired_span_of(0, 0));
  return 1;
}

/* Urgency last set on one of s's streams; -1 if none. */
static int mtdr_urgency(wired_wt_session* s) {
  for (usz i = g_n_calls; i > 0; i--)
    if (g_calls[i - 1].kind == 13 && g_calls[i - 1].s == s)
      return g_calls[i - 1].fin;
  return -1;
}

/* Header Type 0x10 (Publisher Priority present, prio) for Group g, alias
 * 1, plus one 1-byte Object. */
static usz mtdr_stream(u64 g, u8 prio, u8* buf) {
  moqdata_subhdr h   = {0};
  usz            off = 0;
  u8             b   = 7;
  h.type             = 0x10;
  h.track_alias      = 1;
  h.group_id         = g;
  h.priority         = prio;
  wired_mspan m      = wired_mspan_of(buf, MOQTRUN_TEST_MAX_PAYLOAD);
  moqdata_subhdr_put(m, &off, &h);
  moqdata_obj_put(m, &off, 0, wired_span_of(&b, 1));
  return off;
}

/* A publishes alice; B, C joined; the hub sets stream urgencies. */
static moqctl_ftn mtdr_prio_setup(void) {
  moqctl_ftn f = mtrq_setup();
  mtst_join(SESS_C);
  mtst_hub.io.stream_priority = mtdr_prio;
  return f;
}

/* Subscriber priority decides first (7.2): B (10) is sent ahead of C
 * (200) on the keep-open relay streams; the header's default priority
 * (Type 0x30) counts as 128. */
static void test_moqtrun_prio_per_subscriber(void) {
  moqctl_params hi = mtst_params_u8(MOQCTL_PARAM_SUBSCRIBER_PRIORITY, 10);
  moqctl_params lo = mtst_params_u8(MOQCTL_PARAM_SUBSCRIBER_PRIORITY, 200);
  moqctl_ftn    f  = mtdr_prio_setup();
  u8            buf[MOQTRUN_TEST_MAX_PAYLOAD];
  mtst_subscribe_p(SESS_B, MTRQ_S1, &f, 2, &hi);
  mtst_subscribe_p(SESS_C, MTRQ_S1, &f, 2, &lo);
  usz n = mtst_stream(3, 1, 1, buf);
  wired_moqt_on_stream_data(&mtst_hub, SESS_A, 2001, wired_span_of(buf, n), 0);
  CHECK(mtdr_urgency(SESS_B) == WIRED_MOQTRUN_URGENCY(10, 128));
  CHECK(mtdr_urgency(SESS_C) == WIRED_MOQTRUN_URGENCY(200, 128));
  CHECK(WIRED_MOQTRUN_URGENCY(10, 128) < WIRED_MOQTRUN_URGENCY(200, 128));
}

/* A one-shot relay (data and FIN together, io.send_uni) is prioritized
 * too, from the header's own Publisher Priority; no SUBSCRIBER_PRIORITY
 * counts as 128. */
static void test_moqtrun_prio_one_shot(void) {
  moqctl_ftn f = mtdr_prio_setup();
  u8         buf[MOQTRUN_TEST_MAX_PAYLOAD];
  mtst_subscribe_p(SESS_B, MTRQ_S1, &f, 2, 0);
  usz n = mtdr_stream(3, 5, buf);
  wired_moqt_on_stream_data(&mtst_hub, SESS_A, 2001, wired_span_of(buf, n), 1);
  CHECK(moqtrun_test_count_kind(4) == 1);
  CHECK(mtdr_urgency(SESS_B) == WIRED_MOQTRUN_URGENCY(128, 5));
}

/* REQUEST_UPDATE's SUBSCRIBER_PRIORITY applies to streams opened after it
 * (7.1), including a late open on a stream already being relayed. */
static void test_moqtrun_prio_update_applies(void) {
  moqctl_params p = mtst_params_u8(MOQCTL_PARAM_SUBSCRIBER_PRIORITY, 250);
  moqctl_ftn    f = mtdr_prio_setup();
  u8            buf[MOQTRUN_TEST_MAX_PAYLOAD];
  mtst_subscribe_p(SESS_B, MTRQ_S1, &f, 2, 0);
  usz n = mtst_stream(3, 1, 1, buf);
  wired_moqt_on_stream_data(&mtst_hub, SESS_A, 2001, wired_span_of(buf, n), 0);
  CHECK(mtdr_urgency(SESS_B) == WIRED_MOQTRUN_URGENCY(128, 128));
  mtup_update(SESS_B, MTRQ_S1, &p);
  n = mtst_stream(4, 1, 1, buf);
  wired_moqt_on_stream_data(&mtst_hub, SESS_A, 2005, wired_span_of(buf, n), 0);
  CHECK(mtdr_urgency(SESS_B) == WIRED_MOQTRUN_URGENCY(250, 128));
  mtst_subscribe_p(SESS_C, MTRQ_S1, &f, 2, &p);
  n = mtst_stream(4, 1, 0, buf);
  wired_moqt_on_stream_data(&mtst_hub, SESS_A, 2005, wired_span_of(buf, n), 0);
  CHECK(mtdr_urgency(SESS_C) == WIRED_MOQTRUN_URGENCY(250, 128));
}

/* Without the io op nothing is called (old tables). */
static void test_moqtrun_prio_op_absent(void) {
  moqctl_ftn f = mtrq_setup();
  u8         buf[MOQTRUN_TEST_MAX_PAYLOAD];
  mtst_subscribe_p(SESS_B, MTRQ_S1, &f, 2, 0);
  usz n = mtst_stream(3, 1, 1, buf);
  wired_moqt_on_stream_data(&mtst_hub, SESS_A, 2001, wired_span_of(buf, n), 0);
  CHECK(moqtrun_test_count_kind(5) == 1);
  CHECK(moqtrun_test_count_kind(13) == 0);
}

/* ===================== GOAWAY received (10.4) ===================== */

static u64 mtdr_ctl(wired_wt_session* s) {
  return moqtrun_find_by_wt(&mtst_hub, s)->control_stream_id;
}

/* How many times the hub closed s; *last is the last close's code. */
static usz mtdr_closes(wired_wt_session* s, u64* last) {
  usz n = 0;
  for (usz i = 0; i < g_n_calls; i++)
    if (g_calls[i].kind == 11 && g_calls[i].s == s) {
      n++;
      *last = g_calls[i].stream_id;
    }
  return n;
}

/* The first GOAWAY on the control stream is recorded and the session
 * stays; a second is a PROTOCOL_VIOLATION. */
static void test_moqtrun_peer_goaway_twice(void) {
  static const u8 away[] = {0x00, 0x00}; /* no URI, Timeout 0 */
  u64             code   = 0;
  mtrq_setup();
  mtrq_raw(SESS_B, mtdr_ctl(SESS_B), MOQCTL_T_GOAWAY, away, sizeof away);
  CHECK(mtdr_closes(SESS_B, &code) == 0);
  mtrq_raw(SESS_B, mtdr_ctl(SESS_B), MOQCTL_T_GOAWAY, away, sizeof away);
  CHECK(mtdr_closes(SESS_B, &code) == 1);
  CHECK(code == WIRED_MOQTRUN_CLOSE_PROTOCOL_VIOLATION);
}

/* A server receiving a non-zero New Session URI MUST close with
 * PROTOCOL_VIOLATION (10.4), as for a malformed GOAWAY. */
static void test_moqtrun_peer_goaway_uri(void) {
  static const u8 uri[] = {0x01, 'x', 0x00};
  static const u8 bad[] = {0x05};
  u64             code  = 0;
  mtrq_setup();
  mtrq_raw(SESS_B, mtdr_ctl(SESS_B), MOQCTL_T_GOAWAY, uri, sizeof uri);
  CHECK(mtdr_closes(SESS_B, &code) == 1);
  CHECK(code == WIRED_MOQTRUN_CLOSE_PROTOCOL_VIOLATION);
  mtrq_raw(SESS_A, mtdr_ctl(SESS_A), MOQCTL_T_GOAWAY, bad, sizeof bad);
  CHECK(mtdr_closes(SESS_A, &code) == 1);
}

/* ===================== GOAWAY sent (3.6, 10.4) ===================== */

/* Messages of type the hub sent on stream sid (any round kind). */
static usz mtdr_sent(u64 sid, u64 type) {
  usz n = 0;
  for (usz i = 0; i < g_n_calls; i++)
    n += (g_calls[i].kind == 3 || g_calls[i].kind == 12) &&
         g_calls[i].stream_id == sid && mtrq_type_of(&g_calls[i]) == type;
  return n;
}

/* Body of the GOAWAY last sent on sid; 0 if none. */
static int mtdr_goaway_body(u64 sid, wired_span* body) {
  for (usz i = g_n_calls; i > 0; i--) {
    const moqtrun_test_call* c   = &g_calls[i - 1];
    usz                      off = 0;
    u64                      type;
    if (c->kind != 3 || c->stream_id != sid) continue;
    if (moqctl_peek_type(
            wired_span_of(c->payload, c->payload_len), &off, &type, body) !=
            MOQCTL_OK ||
        type != MOQCTL_T_GOAWAY)
      continue;
    return 1;
  }
  return 0;
}

/* The GOAWAY last sent on sid, decoded whole into *g by take; 0 if none
 * or if take leaves bytes over. */
static int mtdr_goaway_by(
    u64 sid, int (*take)(wired_span, usz*, moqctl_goaway*), moqctl_goaway* g) {
  wired_span body;
  usz        boff = 0;
  if (!mtdr_goaway_body(sid, &body)) return 0;
  return take(body, &boff, g) == MOQCTL_OK && boff == body.n;
}

static int mtdr_goaway_on(u64 sid, moqctl_goaway* g) {
  return mtdr_goaway_by(sid, moqctl_goaway_take, g);
}

/* Exactly one GOAWAY per open session, on its control stream, carrying
 * the URI and Timeout; a repeat call sends nothing. */
static void test_moqtrun_goaway_once_per_session(void) {
  moqctl_goaway g;
  mtrq_setup();
  CHECK(wired_moqt_goaway(&mtst_hub, mtst_z("https://h/b"), 500) == 2);
  CHECK(mtdr_sent(mtdr_ctl(SESS_A), MOQCTL_T_GOAWAY) == 1);
  CHECK(mtdr_sent(mtdr_ctl(SESS_B), MOQCTL_T_GOAWAY) == 1);
  CHECK(mtdr_goaway_on(mtdr_ctl(SESS_B), &g));
  CHECK(g.timeout == 500 && g.new_session_uri.n == 11);
  CHECK(wired_moqt_goaway(&mtst_hub, mtst_z(""), 0) == 0);
  CHECK(mtdr_sent(mtdr_ctl(SESS_B), MOQCTL_T_GOAWAY) == 1);
}

/* draft-18 SS10.4: the GOAWAY to a draft-18 session carries the smallest
 * peer Request ID not processed (0 at a server that processed none); a
 * draft-19 session's carries none. */
static void test_moqtrun_goaway_request_id_d18(void) {
  moqctl_goaway g;
  moqctl_ftn    f                            = mtrq_setup();
  moqtrun_find_by_wt(&mtst_hub, SESS_B)->ver = MOQVER_D18;
  mtst_join(SESS_C);
  moqtrun_find_by_wt(&mtst_hub, SESS_C)->ver = MOQVER_D18;
  mtst_subscribe_p(SESS_B, MTRQ_S1, &f, 2, 0);
  CHECK(wired_moqt_goaway(&mtst_hub, mtst_z(""), 500) == 3);
  CHECK(mtdr_goaway_by(mtdr_ctl(SESS_B), moqctl_goaway18_take, &g));
  CHECK(g.timeout == 500 && g.request_id == 4);
  CHECK(mtdr_goaway_by(mtdr_ctl(SESS_C), moqctl_goaway18_take, &g));
  CHECK(g.request_id == 0);
  mtrq_setup();
  CHECK(wired_moqt_goaway(&mtst_hub, mtst_z(""), 500) == 2);
  CHECK(mtdr_goaway_on(mtdr_ctl(SESS_B), &g));
}

/* The largest Request ID a varint can carry still leaves a watermark at
 * or past it: the "+ 2" saturates instead of wrapping to 0. */
static void test_moqtrun_goaway_request_id_saturates(void) {
  moqctl_goaway g;
  moqctl_ftn    f                            = mtrq_setup();
  moqtrun_find_by_wt(&mtst_hub, SESS_B)->ver = MOQVER_D18;
  mtst_subscribe_p(SESS_B, MTRQ_S1, &f, ~(u64)1, 0);
  wired_moqt_goaway(&mtst_hub, mtst_z(""), 500);
  CHECK(mtdr_goaway_by(mtdr_ctl(SESS_B), moqctl_goaway18_take, &g));
  CHECK(g.request_id == ~(u64)0);
}

/* A request whose Request ID cannot be read moves no watermark: the
 * GOAWAY still names the one after the last readable ID. */
static void test_moqtrun_goaway_request_id_ignores_malformed(void) {
  moqctl_goaway g;
  moqctl_ftn    f                            = mtrq_setup();
  moqtrun_find_by_wt(&mtst_hub, SESS_B)->ver = MOQVER_D18;
  mtst_subscribe_p(SESS_B, MTRQ_S1, &f, 2, 0);
  mtrq_raw(SESS_B, MTRQ_S2, MOQCTL_T_SUBSCRIBE, 0, 0);
  wired_moqt_goaway(&mtst_hub, mtst_z(""), 500);
  CHECK(mtdr_goaway_by(mtdr_ctl(SESS_B), moqctl_goaway18_take, &g));
  CHECK(g.request_id == 4);
}

/* A draft-18 peer's control-stream GOAWAY must carry its Request ID: one
 * without is malformed (PROTOCOL_VIOLATION), one with it is recorded. */
static void test_moqtrun_peer_goaway_d18(void) {
  static const u8 bare[] = {0x00, 0x00};
  static const u8 rid[]  = {0x00, 0x00, 0x01};
  u64             code   = 0;
  mtrq_setup();
  moqtrun_find_by_wt(&mtst_hub, SESS_A)->ver = MOQVER_D18;
  moqtrun_find_by_wt(&mtst_hub, SESS_B)->ver = MOQVER_D18;
  mtrq_raw(SESS_A, mtdr_ctl(SESS_A), MOQCTL_T_GOAWAY, rid, sizeof rid);
  CHECK(mtdr_closes(SESS_A, &code) == 0);
  mtrq_raw(SESS_B, mtdr_ctl(SESS_B), MOQCTL_T_GOAWAY, bare, sizeof bare);
  CHECK(mtdr_closes(SESS_B, &code) == 1);
  CHECK(code == WIRED_MOQTRUN_CLOSE_PROTOCOL_VIOLATION);
}

/* draft-18 SS10.4: the Request ID names one of the hub's own (odd, server)
 * Request IDs; an even one closes with INVALID_REQUEST_ID. */
static void test_moqtrun_peer_goaway_d18_parity(void) {
  static const u8 even[] = {0x00, 0x00, 0x02};
  u64             code   = 0;
  mtrq_setup();
  moqtrun_find_by_wt(&mtst_hub, SESS_B)->ver = MOQVER_D18;
  mtrq_raw(SESS_B, mtdr_ctl(SESS_B), MOQCTL_T_GOAWAY, even, sizeof even);
  CHECK(mtdr_closes(SESS_B, &code) == 1);
  CHECK(code == WIRED_MOQTRUN_CLOSE_INVALID_REQUEST_ID);
}

/* A URI past WIRED_MOQTRUN_GOAWAY_URI_MAX is refused whole. */
static void test_moqtrun_goaway_uri_too_long(void) {
  static u8 uri[WIRED_MOQTRUN_GOAWAY_URI_MAX + 1];
  mtrq_setup();
  moqtrun_test_reset();
  CHECK(wired_moqt_goaway(&mtst_hub, wired_span_of(uri, sizeof uri), 1) == -1);
  CHECK(g_n_calls == 0);
  CHECK(
      wired_moqt_goaway(&mtst_hub, wired_span_of(uri, sizeof uri - 1), 1) == 2);
}

/* After GOAWAY on its session a new request is refused GOING_AWAY and
 * creates nothing, on a request stream or the control stream; one already
 * answered stays, and its REQUEST_UPDATE is still served. */
static void test_moqtrun_goaway_late_rejected(void) {
  moqctl_params p = mtst_params_u8(MOQCTL_PARAM_SUBSCRIBER_PRIORITY, 9);
  moqctl_ftn    f = mtrq_setup();
  mtst_subscribe_p(SESS_B, MTRQ_S1, &f, 2, 0);
  wired_moqt_goaway(&mtst_hub, mtst_z(""), 500);
  mtst_subscribe_p(SESS_B, MTRQ_S2, &f, 4, 0);
  CHECK(mtup_err_code(MTRQ_S2) == MOQCTL_ERR_GOING_AWAY);
  CHECK(mtrq_fin_on(MTRQ_S2) == 1);
  mtst_subscribe(SESS_B, mtdr_ctl(SESS_B), &f);
  CHECK(mtdr_sent(mtdr_ctl(SESS_B), MOQCTL_T_REQUEST_ERROR) == 1);
  mtup_update(SESS_B, MTRQ_S1, &p);
  CHECK(mtup_reply(MTRQ_S1, &(wired_span){0, 0}) == MOQCTL_T_REQUEST_OK);
  wired_moqtrun_sub* s = mtst_sub(SESS_A, SESS_B);
  CHECK(s && s->request_id == 2 && s->priority == 9);
}

/* WT_DRAIN_SESSION from one peer is a GOAWAY to that session only. */
static void test_moqtrun_drain_one_session(void) {
  moqctl_ftn f = mtrq_setup();
  wired_moqt_on_session_draining(&mtst_hub, SESS_A);
  CHECK(mtdr_sent(mtdr_ctl(SESS_A), MOQCTL_T_GOAWAY) == 1);
  CHECK(mtdr_sent(mtdr_ctl(SESS_B), MOQCTL_T_GOAWAY) == 0);
  mtst_subscribe_p(SESS_B, MTRQ_S1, &f, 2, 0);
  CHECK(mtrq_type_on(12, MTRQ_S1) == MOQCTL_T_SUBSCRIBE_OK);
  wired_moqt_on_session_draining(&mtst_hub, SESS_A);
  CHECK(mtdr_sent(mtdr_ctl(SESS_A), MOQCTL_T_GOAWAY) == 1);
}

/* ===================== PUBLISH_DONE (10.11) ===================== */

/* Status of the PUBLISH_DONE sent in call c; ~0 if it carries none.
 * *count gets its Stream Count. A round may carry several messages. */
static u64 mtdr_done_in(const moqtrun_test_call* c, u64* count) {
  wired_span          all = wired_span_of(c->payload, c->payload_len);
  usz                 off = 0, boff = 0;
  u64                 type;
  wired_span          body;
  moqctl_publish_done d;
  while (moqctl_peek_type(all, &off, &type, &body) == MOQCTL_OK)
    if (type == MOQCTL_T_PUBLISH_DONE &&
        moqctl_publish_done_take(body, &boff, &d) == MOQCTL_OK) {
      *count = d.stream_count;
      return d.status_code;
    }
  return ~(u64)0;
}

/* Status of the last PUBLISH_DONE sent on sid; ~0 if none. */
static u64 mtdr_done_on(u64 sid, u64* count) {
  for (usz i = g_n_calls; i > 0; i--) {
    const moqtrun_test_call* c = &g_calls[i - 1];
    if ((c->kind != 3 && c->kind != 12) || c->stream_id != sid) continue;
    u64 st = mtdr_done_in(c, count);
    if (st != ~(u64)0) return st;
  }
  return ~(u64)0;
}

/* The publisher's session ending ends its subscribers' subscriptions:
 * PUBLISH_DONE TRACK_ENDED, then FIN, and a rejoin does not revive them.
 * A subscription on the control stream has no stream to carry it and is
 * kept for the rejoin as before. */
static void test_moqtrun_done_track_ended(void) {
  moqctl_ftn f     = mtrq_setup();
  u64        count = 0;
  mtst_join(SESS_C);
  mtst_subscribe_p(SESS_B, MTRQ_S1, &f, 2, 0);
  mtst_subscribe(SESS_C, mtdr_ctl(SESS_C), &f);
  wired_moqt_on_session_close(&mtst_hub, SESS_A);
  CHECK(mtdr_done_on(MTRQ_S1, &count) == MOQCTL_DONE_TRACK_ENDED);
  CHECK(count == MOQTRUN_DONE_STREAMS_UNKNOWN);
  CHECK(mtrq_fin_on(MTRQ_S1) == 1);
  CHECK(mtdr_sent(mtdr_ctl(SESS_C), MOQCTL_T_PUBLISH_DONE) == 0);
  mtst_publish(SESS_A, mtst_join(SESS_A), &f, 1);
  CHECK(mtst_sub(SESS_A, SESS_B) == 0);
  CHECK(mtst_sub(SESS_A, SESS_C) != 0);
}

/* draft-22 SS9.9: the "unknown" Stream Count is 2^64-1 (a 9-byte
 * vi64); draft-18/19 keep 2^62-1 (test_moqtrun_done_track_ended). */
static void test_moqtrun_done_stream_count_d22(void) {
  moqctl_ftn f                               = mtrq_setup();
  u64        count                           = 0;
  moqtrun_find_by_wt(&mtst_hub, SESS_B)->ver = MOQVER_D22;
  mtst_subscribe_p(SESS_B, MTRQ_S1, &f, 2, 0);
  wired_moqt_on_session_close(&mtst_hub, SESS_A);
  CHECK(mtdr_done_on(MTRQ_S1, &count) == MOQCTL_DONE_TRACK_ENDED);
  CHECK(count == ~(u64)0);
}

/* Id of the last keep-open relay stream opened to s (io kind 5). */
static u64 mtdr_uni_sid(wired_wt_session* s) {
  for (usz i = g_n_calls; i > 0; i--)
    if (g_calls[i - 1].kind == 5 && g_calls[i - 1].s == s)
      return g_calls[i - 1].stream_id;
  return ~(u64)0;
}

/* Call index of the first reset of sid (*code its code); g_n_calls if
 * none. */
static usz mtdr_reset_at(u64 sid, int* code) {
  for (usz i = 0; i < g_n_calls; i++)
    if (g_calls[i].kind == 7 && g_calls[i].stream_id == sid) {
      *code = g_calls[i].fin;
      return i;
    }
  return g_n_calls;
}

/* Call index of the first round on sid carrying a PUBLISH_DONE. */
static usz mtdr_done_at(u64 sid) {
  u64 count;
  for (usz i = 0; i < g_n_calls; i++)
    if ((g_calls[i].kind == 3 || g_calls[i].kind == 12) &&
        g_calls[i].stream_id == sid &&
        mtdr_done_in(&g_calls[i], &count) != ~(u64)0)
      return i;
  return g_n_calls;
}

/* 10.11: every stream the hub opened for a subscription is closed before
 * its PUBLISH_DONE -- the open relay stream is reset first (CANCELLED for
 * a track that ended). A control-stream subscriber's stream is still
 * reset by the republish's stale-relay walk, as before. */
static void test_moqtrun_done_resets_streams_first(void) {
  moqctl_ftn f = mtrq_setup();
  u8         buf[MOQTRUN_TEST_MAX_PAYLOAD];
  int        code = -1;
  mtst_join(SESS_C);
  mtst_subscribe_p(SESS_B, MTRQ_S1, &f, 2, 0);
  mtst_subscribe(SESS_C, mtdr_ctl(SESS_C), &f);
  usz n = mtst_stream(3, 1, 1, buf);
  wired_moqt_on_stream_data(&mtst_hub, SESS_A, 2001, wired_span_of(buf, n), 0);
  u64 sb = mtdr_uni_sid(SESS_B), sc = mtdr_uni_sid(SESS_C);
  wired_moqt_on_session_close(&mtst_hub, SESS_A);
  usz at = mtdr_reset_at(sb, &code);
  CHECK(at < mtdr_done_at(MTRQ_S1));
  CHECK(code == MOQTRUN_RESET_CANCELLED);
  CHECK(mtdr_reset_at(sc, &code) == g_n_calls);
  mtst_publish(SESS_A, mtst_join(SESS_A), &f, 1);
  CHECK(mtdr_reset_at(sc, &code) < g_n_calls);
  CHECK(mtdr_reset_at(sb, &code) == at); /* reset once */
}

/* A failed update resets the subscription's open stream before its
 * PUBLISH_DONE UPDATE_FAILED too. */
static void test_moqtrun_upd_failed_resets_first(void) {
  moqctl_params p = mtup_vi(MOQCTL_PARAM_SUBGROUP_DELIVERY_TIMEOUT, 9);
  moqctl_ftn    f = mtrq_setup();
  u8            buf[MOQTRUN_TEST_MAX_PAYLOAD];
  int           code = -1;
  mtst_subscribe_p(SESS_B, MTRQ_S1, &f, 2, 0);
  usz n = mtst_stream(3, 1, 1, buf);
  wired_moqt_on_stream_data(&mtst_hub, SESS_A, 2001, wired_span_of(buf, n), 0);
  u64 sb = mtdr_uni_sid(SESS_B);
  mtup_update(SESS_B, MTRQ_S1, &p);
  CHECK(mtdr_reset_at(sb, &code) < mtdr_done_at(MTRQ_S1));
  CHECK(code == MOQTRUN_RESET_CANCELLED);
}

/* ===================== GOAWAY timeout (3.6) ===================== */

/* Past the Timeout, the hub flushes first -- PUBLISH_DONE GOING_AWAY to
 * every subscription the session holds, its stream FINed -- and closes
 * with GOAWAY_TIMEOUT only after WIRED_MOQTRUN_GOAWAY_GRACE_MS more have
 * passed since the flush, never on the very next tick: a peer under load
 * needs real wall-clock time to read the flushed bytes before its session
 * is torn down (a fixed guide sample hit this as a flaky CI failure when
 * the close landed before the client had read the reset relay stream).
 * The clock is the tick's. */
static void test_moqtrun_goaway_timeout_flush_then_close(void) {
  moqctl_ftn f     = mtrq_setup();
  u64        count = 0, code = 0;
  int        rcode = -1;
  u8         buf[MOQTRUN_TEST_MAX_PAYLOAD];
  mtst_join(SESS_C);
  mtst_subscribe_p(SESS_B, MTRQ_S1, &f, 2, 0);
  usz n = mtst_stream(3, 1, 1, buf);
  wired_moqt_on_stream_data(&mtst_hub, SESS_A, 2001, wired_span_of(buf, n), 0);
  u64 sb = mtdr_uni_sid(SESS_B);
  wired_moqt_tick(&mtst_hub, 1000);
  wired_moqt_goaway(&mtst_hub, mtst_z(""), 500);
  wired_moqt_tick(&mtst_hub, 1499);
  CHECK(mtdr_done_on(MTRQ_S1, &count) == ~(u64)0);
  CHECK(mtdr_closes(SESS_B, &code) == 0);
  wired_moqt_tick(&mtst_hub, 1500);
  CHECK(mtdr_done_on(MTRQ_S1, &count) == MOQCTL_DONE_GOING_AWAY);
  CHECK(mtdr_reset_at(sb, &rcode) < mtdr_done_at(MTRQ_S1));
  CHECK(rcode == MOQTRUN_RESET_GOING_AWAY);
  CHECK(mtrq_fin_on(MTRQ_S1) == 1);
  CHECK(mtst_sub(SESS_A, SESS_B) == 0);
  CHECK(mtdr_closes(SESS_B, &code) == 0);
  /* Still within the grace window: no close yet, no matter how many ticks
   * land (a slow peer gets the same grace a fast one does). */
  wired_moqt_tick(&mtst_hub, 1501);
  CHECK(mtdr_closes(SESS_B, &code) == 0);
  wired_moqt_tick(&mtst_hub, 1500 + WIRED_MOQTRUN_GOAWAY_GRACE_MS);
  CHECK(mtdr_closes(SESS_B, &code) == 0);
  wired_moqt_tick(&mtst_hub, 1500 + WIRED_MOQTRUN_GOAWAY_GRACE_MS + 1);
  CHECK(mtdr_closes(SESS_B, &code) == 1); /* its request stream is open */
  CHECK(code == WIRED_MOQTRUN_CLOSE_GOAWAY_TIMEOUT);
  CHECK(mtdr_closes(SESS_A, &code) == 1); /* it publishes a track */
  CHECK(code == WIRED_MOQTRUN_CLOSE_GOAWAY_TIMEOUT);
  CHECK(mtdr_closes(SESS_C, &code) == 1); /* nothing open */
  CHECK(code == WIRED_MOQTRUN_CLOSE_NO_ERROR);
  wired_moqt_tick(&mtst_hub, 1500 + WIRED_MOQTRUN_GOAWAY_GRACE_MS + 2);
  CHECK(mtdr_closes(SESS_B, &code) == 1); /* closed once */
}

/* Timeout 0 sets no deadline (10.4); the session stays open. */
static void test_moqtrun_goaway_no_timeout(void) {
  u64 code = 0;
  mtrq_setup();
  wired_moqt_goaway(&mtst_hub, mtst_z(""), 0);
  wired_moqt_tick(&mtst_hub, (u64)1 << 40);
  CHECK(mtdr_closes(SESS_A, &code) == 0);
  CHECK(mtdr_closes(SESS_B, &code) == 0);
}

/* Nothing goes to a session the hub closed: no GOAWAY, no PUBLISH_DONE
 * when its publisher leaves. */
static void test_moqtrun_closed_is_frozen(void) {
  static const u8 away[] = {0x00, 0x00};
  moqctl_ftn      f      = mtrq_setup();
  u64             count  = 0;
  mtst_subscribe_p(SESS_B, MTRQ_S1, &f, 2, 0);
  mtrq_raw(SESS_B, mtdr_ctl(SESS_B), MOQCTL_T_GOAWAY, away, sizeof away);
  mtrq_raw(SESS_B, mtdr_ctl(SESS_B), MOQCTL_T_GOAWAY, away, sizeof away);
  CHECK(wired_moqt_goaway(&mtst_hub, mtst_z(""), 1) == 1);
  CHECK(mtdr_sent(mtdr_ctl(SESS_B), MOQCTL_T_GOAWAY) == 0);
  wired_moqt_on_session_close(&mtst_hub, SESS_A);
  CHECK(mtdr_done_on(MTRQ_S1, &count) == ~(u64)0);
}

/* ===================== failed REQUEST_UPDATE (10.9.1) ================ */

/* A failed update of a subscription also ends it: REQUEST_ERROR, then
 * PUBLISH_DONE UPDATE_FAILED, then FIN; no more Objects reach it. */
static void test_moqtrun_upd_failed_ends_subscription(void) {
  moqctl_params p     = mtup_vi(MOQCTL_PARAM_SUBGROUP_DELIVERY_TIMEOUT, 9);
  moqctl_ftn    f     = mtrq_setup();
  u64           count = 0;
  mtst_subscribe_p(SESS_B, MTRQ_S1, &f, 2, 0);
  mtup_update(SESS_B, MTRQ_S1, &p);
  CHECK(mtup_err_code(MTRQ_S1) == MOQCTL_ERR_NOT_SUPPORTED);
  CHECK(mtdr_done_on(MTRQ_S1, &count) == MOQCTL_DONE_UPDATE_FAILED);
  CHECK(mtrq_fin_on(MTRQ_S1) == 1);
  CHECK(mtst_sub(SESS_A, SESS_B) == 0);
  CHECK(moqtrun_test_relay_alice_chat(&mtst_hub) == 0);
}

/* A failed update of a namespace request closes its bidi stream (10.9.1,
 * 3.3.2): the hub FINs after REQUEST_ERROR, and a withdrawn
 * PUBLISH_NAMESPACE is NAMESPACE_DONE to its subscribers. */
static void test_moqtrun_upd_failed_closes_ns(void) {
  static const u8 upd[] = {0x02, 0x00}; /* Request ID 2, no parameters */
  mtns_init();
  mtns_sub(SESS_B, MTRQ_S1, "chat");
  mtns_pub(SESS_A, MTRQ_S1, "chat/room1");
  mtrq_raw(SESS_A, MTRQ_S1, MOQTSTAT_T_REQUEST_UPDATE, upd, sizeof upd);
  CHECK(mtns_is(SESS_A, MTRQ_S1, "OK|ERR:03|"));
  CHECK(mtns_is(SESS_B, MTRQ_S1, "OK|NS:room1|DONE:room1|"));
  mtrq_raw(SESS_B, MTRQ_S1, MOQTSTAT_T_REQUEST_UPDATE, upd, sizeof upd);
  CHECK(mtns_is(SESS_B, MTRQ_S1, "OK|NS:room1|DONE:room1|ERR:03|"));
  CHECK(moqtrun_test_count_kind(6) == 2);
  mtns_pub(SESS_A, MTRQ_S2, "chat/room2");
  CHECK(mtns_is(SESS_B, MTRQ_S1, "OK|NS:room1|DONE:room1|ERR:03|"));
}

/* A GOAWAY the control stream refused (previous round unACKed) goes out
 * on the next tick, even if the peer sends nothing more. */
static void test_moqtrun_goaway_retried_on_tick(void) {
  mtrq_setup();
  g_stream_send_reject_n = 2;
  wired_moqt_goaway(&mtst_hub, mtst_z(""), 0);
  CHECK(mtdr_sent(mtdr_ctl(SESS_A), MOQCTL_T_GOAWAY) == 1);
  CHECK(moqtrun_test_last_kind(3)->refused == 1);
  wired_moqt_tick(&mtst_hub, 1);
  CHECK(mtdr_sent(mtdr_ctl(SESS_A), MOQCTL_T_GOAWAY) == 2);
  CHECK(moqtrun_test_last_kind(3)->refused == 0);
}

void test_moqtrun_drain(void) {
  test_moqtrun_done_resets_streams_first();
  test_moqtrun_upd_failed_resets_first();
  test_moqtrun_goaway_retried_on_tick();
  test_moqtrun_upd_failed_ends_subscription();
  test_moqtrun_upd_failed_closes_ns();
  test_moqtrun_goaway_timeout_flush_then_close();
  test_moqtrun_goaway_no_timeout();
  test_moqtrun_closed_is_frozen();
  test_moqtrun_done_track_ended();
  test_moqtrun_done_stream_count_d22();
  test_moqtrun_goaway_once_per_session();
  test_moqtrun_goaway_request_id_d18();
  test_moqtrun_peer_goaway_d18();
  test_moqtrun_goaway_request_id_saturates();
  test_moqtrun_goaway_request_id_ignores_malformed();
  test_moqtrun_peer_goaway_d18_parity();
  test_moqtrun_goaway_uri_too_long();
  test_moqtrun_goaway_late_rejected();
  test_moqtrun_drain_one_session();
  test_moqtrun_peer_goaway_twice();
  test_moqtrun_peer_goaway_uri();
  test_moqtrun_prio_per_subscriber();
  test_moqtrun_prio_one_shot();
  test_moqtrun_prio_update_applies();
  test_moqtrun_prio_op_absent();
}
