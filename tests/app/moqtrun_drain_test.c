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

/* The GOAWAY last sent on sid, decoded into *g; 0 if none. */
static int mtdr_goaway_on(u64 sid, moqctl_goaway* g) {
  for (usz i = g_n_calls; i > 0; i--) {
    const moqtrun_test_call* c   = &g_calls[i - 1];
    usz                      off = 0, boff = 0;
    u64                      type;
    wired_span               body;
    if (c->kind != 3 || c->stream_id != sid) continue;
    if (moqctl_peek_type(
            wired_span_of(c->payload, c->payload_len), &off, &type, &body) !=
            MOQCTL_OK ||
        type != MOQCTL_T_GOAWAY)
      continue;
    return moqctl_goaway_take(body, &boff, g) == MOQCTL_OK;
  }
  return 0;
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

void test_moqtrun_drain(void) {
  test_moqtrun_goaway_once_per_session();
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
