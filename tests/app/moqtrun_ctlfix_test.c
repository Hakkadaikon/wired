/* Control-stream fixes from the 7-1 TLC counterexamples (ledger 12-12,
 * 12-13). Shares the recording io stubs and fixtures of moqtrun_test.c,
 * moqtrun_sub_test.c, moqtrun_fetch_test.c and moqtrun_fill_test.c (same
 * unity TU). */

/* ====== 12-12: SETUP split inside its Type varint (RFC 9000 2.2) ====== */

/* A token session (moqt-NN for the current draft) on SESS_A. */
static void mtcf_token_session(wired_moqt_hub* hub) {
  moqtrun_test_reset();
  wired_moqt_init(hub, moqtrun_test_io());
  wired_moqt_on_session(
      hub, SESS_A, wired_span_of(0, 0),
      moqtrun_test_proto(moqtrun_test_ver_tok()));
}

/* Delivers msg[from, to) on sid without FIN. */
static void mtcf_part(
    wired_moqt_hub* hub, u64 sid, const u8* msg, usz from, usz to) {
  wired_moqt_on_stream_data(
      hub, SESS_A, sid, wired_span_of(msg + from, to - from), 0);
}

/* draft-22 6.3 / draft-19 3.3: the client's uni control stream arrives
 * as 0xAF alone (the first byte of SETUP's 2-byte Type), a SUBSCRIBE
 * request is held meanwhile, then the rest: the session establishes and
 * the held SUBSCRIBE is answered. */
static void test_mtcf_uni_split_in_type(void) {
  wired_moqt_hub hub;
  u8             msg[16];
  usz            n = mtctl_uni_ctl(msg, 0, 0);
  mtcf_token_session(&hub);
  mtcf_part(&hub, 2, msg, 0, 1);
  wired_moqt_on_stream_data(
      &hub, SESS_A, 0,
      wired_span_of(g_moqt_ctl_subscribe_basic, G_MOQT_CTL_SUBSCRIBE_BASIC_LEN),
      0);
  CHECK(moqtrun_test_count_kind(12) == 0); /* held until established */
  mtcf_part(&hub, 2, msg, 1, n);
  CHECK(moqsess_established(&hub.peers[0].sess));
  CHECK(moqtrun_test_count_kind(12) == 1); /* the held SUBSCRIBE answered */
  CHECK(moqtrun_test_count_kind(11) == 0);
}

/* The bidi twin: a SETUP-first client bidi split inside its Type is the
 * client control stream, not a request stream. */
static void test_mtcf_bidi_split_in_type(void) {
  wired_moqt_hub hub;
  u8             msg[16];
  usz            n = mtctl_setup_msg(msg, 0, 0);
  mtcf_token_session(&hub);
  mtcf_part(&hub, 0, msg, 0, 1);
  mtcf_part(&hub, 0, msg, 1, n);
  CHECK(moqsess_established(&hub.peers[0].sess));
  CHECK(hub.peers[0].peer_ctl_set && hub.peers[0].peer_ctl_stream_id == 0);
  CHECK(moqtrun_test_count_kind(12) == 0); /* no request reply */
  CHECK(moqtrun_test_count_kind(11) == 0);
}

/* Regression guard: a split right after the whole Type varint. */
static void test_mtcf_uni_split_after_type(void) {
  wired_moqt_hub hub;
  u8             msg[16];
  usz            n = mtctl_uni_ctl(msg, 0, 0);
  mtcf_token_session(&hub);
  mtcf_part(&hub, 2, msg, 0, 2);
  mtcf_part(&hub, 2, msg, 2, n);
  CHECK(moqsess_established(&hub.peers[0].sess));
  CHECK(hub.peers[0].setup_recv == 1);
  CHECK(moqtrun_test_count_kind(11) == 0);
}

/* One byte per delivery, MOQT_IMPLEMENTATION included. */
static void test_mtcf_uni_byte_at_a_time(void) {
  static const u8 impl[] = {0x07, 0x01, 'w'};
  wired_moqt_hub  hub;
  u8              msg[16];
  usz             n = mtctl_uni_ctl(msg, impl, sizeof impl);
  mtcf_token_session(&hub);
  for (usz i = 0; i < n; i++) mtcf_part(&hub, 2, msg, i, i + 1);
  CHECK(moqsess_established(&hub.peers[0].sess));
  CHECK(hub.peers[0].peer_has_impl == 1);
  CHECK(moqtrun_test_count_kind(11) == 0);
}

/* == 12-13: a parameter outside the sender's draft closes the session == */

/* draft-19 10.2 (draft-18 10.2, draft-22 9.20): an unknown Message
 * Parameter MUST close the session with PROTOCOL_VIOLATION. A and B
 * joined, A publishes alice; B runs draft ver. */
static moqctl_ftn mtcf_setup(int ver) {
  moqctl_ftn f                               = mtrq_setup();
  moqtrun_find_by_wt(&mtst_hub, SESS_B)->ver = ver;
  return f;
}

/* params = {one BYTES item of type} (the value never matters: the Type
 * itself is what the sender's draft lacks). */
static moqctl_params mtcf_param(u64 type) {
  static const u8 v[] = {0x00};
  moqctl_params   p   = {0};
  p.items[0].type     = type;
  p.items[0].enc      = MOQCTL_PENC_BYTES;
  p.items[0].bytes    = wired_span_of(v, sizeof v);
  p.n                 = 1;
  return p;
}

/* Closed PROTOCOL_VIOLATION, nothing answered on the request stream. */
static void mtcf_check_violation(void) {
  CHECK(mtrq_closes() == 1);
  CHECK(moqtrun_test_count_kind(12) == 0);
}

static void test_mtcf_d19_subscribe_fill(void) {
  moqctl_ftn    f = mtcf_setup(MOQVER_D19);
  moqctl_params p = mtcf_param(MOQCTL_PARAM_FILL_PARAMETERS);
  mtst_subscribe_p(SESS_B, MTRQ_S1, &f, 2, &p);
  mtcf_check_violation();
}

static void test_mtcf_d18_subscribe_range_filter(void) {
  moqctl_ftn         f  = mtcf_setup(MOQVER_D18);
  moqctl_params      p  = {0};
  moqctl_rangefilter rf = mtst_rngf1(1, 0, 0, 1);
  mtst_rngf_param(&p, MOQCTL_PARAM_SUBGROUP_FILTER, &rf);
  mtst_subscribe_p(SESS_B, MTRQ_S1, &f, 2, &p);
  mtcf_check_violation();
}

static void test_mtcf_d19_publish_include_props(void) {
  moqctl_ftn    f = mtst_ftn("chat", "room1", "bob");
  moqctl_params p = mtcf_param(MOQCTL_PARAM_INCLUDE_PROPERTIES);
  mtcf_setup(MOQVER_D19);
  mtst_publish_p(SESS_B, MTRQ_S1, &f, 7, &p);
  mtcf_check_violation();
}

/* TRACK_STATUS {x}/y, Request ID 0, one parameter FILL_PARAMETERS. */
static void test_mtcf_d19_tstat_fill(void) {
  static const u8 body[] = {0x00, 0x01, 0x01, 0x78, 0x01,
                            0x79, 0x01, 0x23, 0x01, 0x00};
  mtcf_setup(MOQVER_D19);
  mtrq_raw(SESS_B, MTRQ_S1, MOQTSTAT_T_TRACK_STATUS, body, sizeof body);
  mtcf_check_violation();
}

static void mtcf_ns_req(int ver, u64 type, u64 param) {
  static moqns_req m;
  mtcf_setup(ver);
  m.request_id = 2;
  m.ns         = mtns_ns("chat");
  m.params     = mtcf_param(param);
  mtst_send(SESS_B, MTRQ_S1, type, mtns_enc, &m);
  mtcf_check_violation();
}

static void test_mtcf_d18_subtracks_range_filter(void) {
  mtcf_ns_req(
      MOQVER_D18, MOQCTL_T_SUBSCRIBE_TRACKS, MOQCTL_PARAM_SUBGROUP_FILTER);
}

static void test_mtcf_d19_subns_fill(void) {
  mtcf_ns_req(
      MOQVER_D19, MOQNS_T_SUBSCRIBE_NAMESPACE, MOQCTL_PARAM_FILL_PARAMETERS);
}

static void test_mtcf_d19_pubns_fill(void) {
  mtcf_ns_req(
      MOQVER_D19, MOQNS_T_PUBLISH_NAMESPACE, MOQCTL_PARAM_FILL_PARAMETERS);
}

/* Regression guard: the same SUBSCRIBE from a draft-22 subscriber (where
 * FILL_PARAMETERS exists, 9.20.15, LOCATION_FILTER type 0x00) is served:
 * SUBSCRIBE_OK and one fill fetch stream, no close. */
static void test_mtcf_d22_subscribe_fill_served(void) {
  moqfetch_fill fill = {0};
  mf_init(sizeof mf_arena);
  mf_obj(0, 0, 1);
  mfill_subscribe(&fill, 0);
  CHECK(moqtrun_test_count_kind(11) == 0);
  CHECK(mtst_last_ok() != 0);
  CHECK(mf_read());
  CHECK(mfill_opens() == 1);
}

static void mtcf_split_all(void) {
  test_mtcf_uni_split_in_type();
  test_mtcf_bidi_split_in_type();
  test_mtcf_uni_split_after_type();
  test_mtcf_uni_byte_at_a_time();
}

void test_moqtrun_ctlfix(void) {
  moqtrun_test_allver(mtcf_split_all);
  test_mtcf_d19_subscribe_fill();
  test_mtcf_d18_subscribe_range_filter();
  test_mtcf_d19_publish_include_props();
  test_mtcf_d19_tstat_fill();
  test_mtcf_d18_subtracks_range_filter();
  test_mtcf_d19_subns_fill();
  test_mtcf_d19_pubns_fill();
  test_mtcf_d22_subscribe_fill_served();
}
