/* Session-level error handling of the hub (issue #20): malformed peer
 * input closes the MOQT session with the draft's code, through the
 * moqsess model. Shares the recording io stubs and fixtures of
 * moqtrun_test.c, moqtrun_sub_test.c and moqtrun_ctlfix_test.c (same
 * unity TU). */

/* Delivers b on SESS_A's uni stream sid (fin as given). */
static void mtss_uni(u64 sid, const u8* b, usz n, int fin) {
  wired_moqt_on_stream_data(&mtst_hub, SESS_A, sid, wired_span_of(b, n), fin);
}

/* 1 iff the hub's last session close used code. */
static int mtss_closed_with(u64 code) {
  return moqtrun_test_close_code() == code;
}

/* draft-18/19 3.4, draft-22 6.4.1: an unknown uni Stream Type (0x01: bit 4
 * clear, not FETCH_HEADER) closes the session PROTOCOL_VIOLATION, recorded
 * by the moqsess model. */
static void test_mtss_unknown_uni_closes(void) {
  static const u8 b[] = {0x01, 0x01, 0x00, 0x00};
  mtrq_setup();
  mtss_uni(14, b, sizeof b, 0);
  CHECK(mtss_closed_with(WIRED_MOQTRUN_CLOSE_PROTOCOL_VIOLATION));
  CHECK(
      moqtrun_find_by_wt(&mtst_hub, SESS_A)->sess.close_reason ==
      MOQSESS_CLOSE_PROTOCOL_VIOLATION);
}

/* SUBGROUP_ID_MODE 0b11 (Type 0x16) is no SUBGROUP_HEADER either
 * (draft-19 11.4.2): the same close. */
static void test_mtss_subgroup_mode3_closes(void) {
  static const u8 b[] = {0x16, 0x01, 0x00, 0x00, 0x00};
  mtrq_setup();
  mtss_uni(14, b, sizeof b, 0);
  CHECK(mtss_closed_with(WIRED_MOQTRUN_CLOSE_PROTOCOL_VIOLATION));
}

/* Regression guard: a PADDING stream (0x132B3E28, 11.5.1) is known and
 * discarded, the session stays open. */
static void test_mtss_padding_stream_kept(void) {
  u8  b[16];
  usz n  = moqvi_encode(b, MOQDATA_TYPE_PADDING);
  b[n++] = 0xAA;
  mtrq_setup();
  mtss_uni(14, b, n, 1);
  CHECK(moqtrun_test_count_kind(11) == 0);
}

/* draft-19 10.1 (draft-18 10.1, draft-22 6.4.2.1): a client Request ID
 * with the server's (odd) parity closes the session INVALID_REQUEST_ID,
 * recorded by the moqsess model; nothing is answered. */
static void test_mtss_rid_parity_closes(void) {
  moqctl_ftn f = mtrq_setup();
  mtst_subscribe_p(SESS_B, MTRQ_S1, &f, 3, 0);
  CHECK(mtss_closed_with(WIRED_MOQTRUN_CLOSE_INVALID_REQUEST_ID));
  CHECK(
      moqtrun_find_by_wt(&mtst_hub, SESS_B)->sess.close_reason ==
      MOQSESS_CLOSE_INVALID_REQUEST_ID);
  CHECK(moqtrun_test_count_kind(12) == 0);
}

/* The same Request ID on a second request stream is a duplicate. */
static void test_mtss_rid_duplicate_closes(void) {
  moqctl_ftn f = mtrq_setup();
  mtst_subscribe_p(SESS_B, MTRQ_S1, &f, 2, 0);
  CHECK(moqtrun_test_count_kind(11) == 0);
  mtst_subscribe_p(SESS_B, MTRQ_S2, &f, 2, 0);
  CHECK(mtss_closed_with(WIRED_MOQTRUN_CLOSE_INVALID_REQUEST_ID));
}

/* Request streams are independent (RFC 9000 2.2): Request ID 4 arriving
 * before 2 is no duplicate, both are answered and the session stays
 * open; a later 2 or 4 is one. */
static void test_mtss_rid_out_of_order_ok(void) {
  moqctl_ftn f = mtrq_setup();
  mtst_subscribe_p(SESS_B, MTRQ_S2, &f, 4, 0);
  mtst_subscribe_p(SESS_B, MTRQ_S1, &f, 2, 0);
  CHECK(moqtrun_test_count_kind(11) == 0);
  CHECK(mtrq_type_on(12, MTRQ_S1) == MOQCTL_T_SUBSCRIBE_OK);
  CHECK(mtrq_type_on(12, MTRQ_S2) == MOQCTL_T_SUBSCRIBE_OK);
  mtst_subscribe_p(SESS_B, 12, &f, 4, 0);
  CHECK(mtss_closed_with(WIRED_MOQTRUN_CLOSE_INVALID_REQUEST_ID));
}

static void mtss_noop(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, usz peer_idx, wired_span body) {
  (void)hub;
  (void)p;
  (void)peer_idx;
  (void)body;
}

/* 1 iff a SUBSCRIBE with Request ID rid from p passes the Request ID
 * check. */
static int mtss_rid_ok(wired_moqtrun_peer* p, u64 rid) {
  u8  b[9];
  usz n = moqvi_encode(b, rid);
  return moqtrun_rid_gate(
             p, MOQCTL_OK, MOQCTL_T_SUBSCRIBE, wired_span_of(b, n),
             mtss_noop) == mtss_noop;
}

/* A gap the client never fills (Request ID 0, consumed but never sent)
 * does not wedge the check: 64 requests on, the window slides past it,
 * and only then does a late 0 read as used. */
static void test_mtss_rid_window_slides(void) {
  wired_moqtrun_peer* b;
  int                 all = 1;
  mtrq_setup();
  b = moqtrun_find_by_wt(&mtst_hub, SESS_B);
  for (u64 rid = 2; rid <= 140; rid += 2) {
    all &= mtss_rid_ok(b, rid);
  }
  CHECK(all);
  CHECK(!mtss_rid_ok(b, 0));
  CHECK(!mtss_rid_ok(b, 140));
  CHECK(mtss_rid_ok(b, 142));
}

/* draft-19 1.4.3 / 10.2.2: an AUTHORIZATION TOKEN parameter of a SUBSCRIBE
 * whose Token cannot be decoded (USE_VALUE without its Token Type) closes
 * the session KEY_VALUE_FORMATTING_ERROR, not PROTOCOL_VIOLATION -- on a
 * draft-19 session (the decode path is shared by every draft). */
static void test_mtss_request_token_kvfmt(void) {
  static const u8 bad[] = {0x03};
  moqctl_ftn      f     = mtcf_setup(MOQVER_D19);
  moqctl_params   p     = mtcf_param(MOQCTL_PARAM_AUTHORIZATION_TOKEN);
  p.items[0].bytes      = wired_span_of(bad, sizeof bad);
  mtst_subscribe_p(SESS_B, MTRQ_S1, &f, 2, &p);
  CHECK(mtss_closed_with(MOQCTL_CLOSE_KVFMT_ERROR));
  CHECK(moqtrun_test_count_kind(12) == 0);
}

/* A token session on SESS_A whose client SETUP (uni stream 2) carries the
 * Setup Option bytes opt; returns the close code, ~0 for none. */
static u64 mtss_setup_with(const u8* opt, usz n) {
  wired_moqt_hub hub;
  u8             msg[32];
  usz            len = mtctl_uni_ctl(msg, opt, n);
  mtcf_token_session(&hub);
  mtcf_part(&hub, 2, msg, 0, len);
  return moqtrun_test_close_code();
}

/* draft-18 10.3.1.4 / draft-22 9.1.4: a client SETUP AUTHORIZATION TOKEN
 * (option 0x03) with Alias Type DELETE or USE_ALIAS closes the session
 * PROTOCOL_VIOLATION; a REGISTER past the (empty) token cache is used as
 * USE_VALUE -- the session establishes, no AUTH_TOKEN_CACHE_OVERFLOW; an
 * undecodable Token is KEY_VALUE_FORMATTING_ERROR (10.2.2). */
static void test_mtss_setup_token_alias(void) {
  static const u8 del[] = {0x03, 0x02, 0x00, 0x07};
  static const u8 use[] = {0x03, 0x02, 0x02, 0x07};
  static const u8 reg[] = {0x03, 0x04, 0x01, 0x07, 0x01, 'x'};
  static const u8 val[] = {0x03, 0x03, 0x03, 0x01, 'x'};
  static const u8 bad[] = {0x03, 0x01, 0x04};
  CHECK(
      mtss_setup_with(del, sizeof del) ==
      WIRED_MOQTRUN_CLOSE_PROTOCOL_VIOLATION);
  CHECK(
      mtss_setup_with(use, sizeof use) ==
      WIRED_MOQTRUN_CLOSE_PROTOCOL_VIOLATION);
  CHECK(mtss_setup_with(reg, sizeof reg) == ~(u64)0);
  CHECK(mtss_setup_with(val, sizeof val) == ~(u64)0);
  CHECK(mtss_setup_with(bad, sizeof bad) == MOQCTL_CLOSE_KVFMT_ERROR);
}

/* draft-19 11.1 (draft-18 11.1, draft-22 3.1.3): a PUBLISH reusing the
 * Track Alias of another live track of the same session closes it
 * DUPLICATE_TRACK_ALIAS; a re-PUBLISH of the same name under its own
 * alias is the same track and is accepted. */
static void test_mtss_publish_dup_alias_closes(void) {
  moqctl_ftn g = mtst_ftn("chat", "room1", "bob");
  moqctl_ftn f = mtrq_setup(); /* alice, alias 1 */
  mtst_publish(SESS_A, MTRQ_S1, &g, 1);
  CHECK(mtss_closed_with(WIRED_MOQTRUN_CLOSE_DUPLICATE_TRACK_ALIAS));
  CHECK(mtrq_type_on(12, MTRQ_S1) == 0);
  f = mtrq_setup();
  mtst_publish(SESS_A, MTRQ_S1, &f, 1);
  CHECK(moqtrun_test_count_kind(11) == 0);
  CHECK(mtrq_type_on(12, MTRQ_S1) == MOQCTL_T_REQUEST_OK);
}

/* SUBGROUP_HEADER of Type type for A's alice (Track Alias 1), Group 0,
 * then the Object bytes obj; the stream bytes' length. */
static usz mtss_sg(u8* b, u64 type, const u8* obj, usz n) {
  moqdata_subhdr h   = {0};
  usz            off = 0;
  h.type             = type;
  h.track_alias      = 1;
  CHECK(moqdata_subhdr_put(wired_mspan_of(b, 64), &off, &h) == MOQDATA_OK);
  bytes_memcpy(b + off, obj, n);
  return off + n;
}

/* 1 iff A's uni stream 14 carrying Type type + obj (fin as given) closes
 * the session PROTOCOL_VIOLATION. */
static int mtss_sg_closes(u64 type, const u8* obj, usz n, int fin) {
  u8 b[64];
  mtrq_setup();
  mtss_uni(14, b, mtss_sg(b, type, obj, n), fin);
  return moqtrun_test_count_kind(11) == 1 &&
         mtss_closed_with(WIRED_MOQTRUN_CLOSE_PROTOCOL_VIOLATION);
}

/* draft-19 11.2.1.1 / 11.2.1.2 / 11.4.2 (draft-18 alike, draft-22
 * 11.1/11.3.1): an unregistered Object Status (0x7F), Object Properties
 * on a non-Normal Object (End of Group), and a cumulative Object ID past
 * 2^64-1 each close the session PROTOCOL_VIOLATION; a well-formed Object
 * does not. */
static void test_mtss_subgroup_object_violations(void) {
  static const u8 status[] = {0x00, 0x00, 0x7F};
  static const u8 props[]  = {0x00, 0x02, 0x02, 0x05, 0x00, 0x03};
  static const u8 wrap[]   = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                              0xFF, 0xFF, 0x01, 'a',  0x00, 0x01, 'b'};
  static const u8 good[]   = {0x00, 0x02, 'h', 'i'};
  CHECK(mtss_sg_closes(0x10, status, sizeof status, 0));
  CHECK(mtss_sg_closes(0x11, props, sizeof props, 0));
  CHECK(mtss_sg_closes(0x10, wrap, sizeof wrap, 0));
  CHECK(!mtss_sg_closes(0x10, good, sizeof good, 1));
  CHECK(moqtrun_test_count_kind(11) == 0);
}

/* draft-19 11.4 (draft-18 11.4, draft-22 11.3): a Subgroup stream ending
 * with a FIN in the middle of a serialized Object closes the session
 * PROTOCOL_VIOLATION -- in its first delivery, or as a bare FIN after a
 * torn tail the relay held back. */
static void test_mtss_subgroup_fin_mid_object(void) {
  static const u8 torn[] = {0x00, 0x05, 'h', 'i'};
  u8              b[64];
  CHECK(mtss_sg_closes(0x10, torn, sizeof torn, 1));
  mtrq_setup();
  mtss_uni(14, b, mtss_sg(b, 0x10, torn, sizeof torn), 0);
  CHECK(moqtrun_test_count_kind(11) == 0);
  mtss_uni(14, b, 0, 1);
  CHECK(mtss_closed_with(WIRED_MOQTRUN_CLOSE_PROTOCOL_VIOLATION));
}

/* A (alice, alias 1) sends datagram b; 1 iff the hub then closed A's
 * session PROTOCOL_VIOLATION. */
static int mtss_dg_closes(const u8* b, usz n) {
  mtrq_setup();
  wired_moqt_on_datagram(&mtst_hub, SESS_A, wired_span_of(b, n));
  return moqtrun_test_count_kind(11) == 1 &&
         mtss_closed_with(WIRED_MOQTRUN_CLOSE_PROTOCOL_VIOLATION);
}

/* draft-19 11 / 11.3.1 (draft-18 11.3.1, draft-22 11.2.1): an
 * OBJECT_DATAGRAM of an invalid Type (0x40: outside 0b00X0XXXX; 0x22:
 * STATUS with END_OF_GROUP), PROPERTIES with a Properties Length of 0, or
 * Properties on a non-Normal Status closes the session PROTOCOL_VIOLATION;
 * a padding datagram (Type 0x132B3E29, 11.5.2) and a well-formed one do
 * not. */
static void test_mtss_datagram_invalid_closes(void) {
  static const u8 bad_type[] = {0x40, 0x01, 0x00, 0x00, 0x00, 'x'};
  static const u8 st_eog[]   = {0x22, 0x01, 0x00, 0x00, 0x00, 0x03};
  static const u8 props0[]   = {0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 'x'};
  static const u8 st_props[] = {0x21, 0x01, 0x00, 0x00, 0x00,
                                0x02, 0x04, 0x01, 0x03};
  static const u8 good[]     = {0x00, 0x01, 0x00, 0x00, 0x00, 'x'};
  u8              pad[16];
  usz             n = moqvi_encode(pad, 0x132B3E29ULL);
  pad[n++]          = 0x00;
  CHECK(mtss_dg_closes(bad_type, sizeof bad_type));
  CHECK(mtss_dg_closes(st_eog, sizeof st_eog));
  CHECK(mtss_dg_closes(props0, sizeof props0));
  CHECK(mtss_dg_closes(st_props, sizeof st_props));
  CHECK(!mtss_dg_closes(pad, n));
  CHECK(!mtss_dg_closes(good, sizeof good));
}

/* draft-22 9.20.15: a parameter outside Table 7 inside FILL_PARAMETERS
 * (AUTHORIZATION TOKEN, which the FETCH scope would admit) closes the
 * session PROTOCOL_VIOLATION before the SUBSCRIBE is answered; the codec
 * reports it as a violation. */
static void test_mtss_fill_unlisted_param_closes(void) {
  static const u8 inner[] = {0x01, 0x03, 0x04, 0x03, 0x01, 'o', 'k'};
  moqfetch_fill   fill;
  moqctl_ftn      f = mtcf_setup(MOQVER_D22);
  moqctl_params   p = mtcf_param(MOQCTL_PARAM_FILL_PARAMETERS);
  p.items[0].bytes  = wired_span_of(inner, sizeof inner);
  CHECK(
      moqfetch_fill_take(wired_span_of(inner, sizeof inner), &fill) ==
      MOQCTL_VIOLATION);
  mtst_subscribe_p(SESS_B, MTRQ_S1, &f, 2, &p);
  mtcf_check_violation();
}

/* A publishes alice; B's SUBSCRIBE_TRACKS "chat" makes the hub PUBLISH it
 * to B; that PUBLISH's stream id. */
static u64 mtss_hub_publish(void) {
  moqctl_ftn f = mtst_ftn("chat", "room1", "alice");
  mtst_init();
  u64 ca = mtst_join(SESS_A);
  mtst_join(SESS_B);
  mtst_publish(SESS_A, ca, &f, 1);
  mtst_subtracks(SESS_B, MTRQ_S1, "chat");
  wired_moqt_tick(&mtst_hub, 0);
  return (u64)mtst_pub_stream_id(0);
}

/* draft-19 10.5 (draft-18 10.5, draft-22 9.3): a PUBLISH_OK carrying Track
 * Properties closes the session PROTOCOL_VIOLATION and opens nothing; an
 * empty one opens the subscription. */
static void test_mtss_publish_ok_props_closes(void) {
  static const u8          props[] = {0x04, 0x01};
  static moqctl_request_ok ok;
  u64                      sid = mtss_hub_publish();
  ok.track_properties          = wired_span_of(props, sizeof props);
  mtst_send(SESS_B, sid, MOQCTL_T_REQUEST_OK, mtsub_encode_request_ok, &ok);
  CHECK(mtss_closed_with(WIRED_MOQTRUN_CLOSE_PROTOCOL_VIOLATION));
  CHECK(mtst_sub(SESS_A, SESS_B) == 0);
  sid = mtss_hub_publish();
  mtst_pub_ok(SESS_B, sid);
  CHECK(moqtrun_test_count_kind(11) == 0);
  CHECK(mtst_sub(SESS_A, SESS_B) != 0);
}

/* draft-19 10.6.1 (draft-18 10.6.1, draft-22 9.4): a REQUEST_ERROR
 * answering the hub's PUBLISH with a Redirect whose Connect URI Length is
 * non-zero closes the session PROTOCOL_VIOLATION; an empty Connect URI
 * (retry on this session) does not. */
static void test_mtss_publish_error_redirect_closes(void) {
  static moqctl_request_error e;
  u64                         sid = mtss_hub_publish();
  e.error_code                    = MOQCTL_ERR_REDIRECT;
  e.has_redirect                  = 1;
  e.redirect.connect_uri          = mtst_z("https://r.example/moq");
  mtst_send(
      SESS_B, sid, MOQCTL_T_REQUEST_ERROR, mtsub_encode_request_error, &e);
  CHECK(mtss_closed_with(WIRED_MOQTRUN_CLOSE_PROTOCOL_VIOLATION));
  sid                    = mtss_hub_publish();
  e.redirect.connect_uri = wired_span_of(0, 0);
  e.redirect.track_name  = mtst_z("z");
  mtst_send(
      SESS_B, sid, MOQCTL_T_REQUEST_ERROR, mtsub_encode_request_error, &e);
  CHECK(moqtrun_test_count_kind(11) == 0);
}

/* draft-19 3.3 / 10: a request stream opening with a response type, and an
 * unknown message type, close the session through the moqsess model
 * (EV_BAD_FIRST, EV_MALFORMED_CTRL): its state is Closed with
 * PROTOCOL_VIOLATION. */
static void test_mtss_sess_model_closes(void) {
  static const u8 body[] = {0x00, 0x00};
  mtrq_setup();
  mtrq_raw(SESS_B, MTRQ_S1, MOQCTL_T_SUBSCRIBE_OK, body, sizeof body);
  CHECK(mtss_closed_with(WIRED_MOQTRUN_CLOSE_PROTOCOL_VIOLATION));
  CHECK(moqtrun_find_by_wt(&mtst_hub, SESS_B)->sess.state == MOQSESS_CLOSED);
  mtrq_setup();
  mtrq_raw(SESS_B, MTRQ_S1, 0x3F, body, sizeof body);
  CHECK(mtss_closed_with(WIRED_MOQTRUN_CLOSE_PROTOCOL_VIOLATION));
  CHECK(
      moqtrun_find_by_wt(&mtst_hub, SESS_B)->sess.close_reason ==
      MOQSESS_CLOSE_PROTOCOL_VIOLATION);
}

void test_moqtrun_sess(void) {
  test_mtss_unknown_uni_closes();
  test_mtss_subgroup_mode3_closes();
  test_mtss_padding_stream_kept();
  test_mtss_rid_parity_closes();
  test_mtss_rid_duplicate_closes();
  test_mtss_rid_out_of_order_ok();
  test_mtss_rid_window_slides();
  test_mtss_request_token_kvfmt();
  test_mtss_setup_token_alias();
  test_mtss_publish_dup_alias_closes();
  test_mtss_subgroup_object_violations();
  test_mtss_subgroup_fin_mid_object();
  test_mtss_datagram_invalid_closes();
  test_mtss_fill_unlisted_param_closes();
  test_mtss_publish_ok_props_closes();
  test_mtss_publish_error_redirect_closes();
  test_mtss_sess_model_closes();
}
