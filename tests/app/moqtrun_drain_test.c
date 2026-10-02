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

void test_moqtrun_drain(void) {
  test_moqtrun_peer_goaway_twice();
  test_moqtrun_peer_goaway_uri();
  test_moqtrun_prio_per_subscriber();
  test_moqtrun_prio_one_shot();
  test_moqtrun_prio_update_applies();
  test_moqtrun_prio_op_absent();
}
