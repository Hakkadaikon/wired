/* Raw-QUIC MoQT sessions in the hub (ledger 13-9, plan S10, T-F1..F4):
 * wired_moqt_on_session_raw, the per-peer raw bit and the PATH/AUTHORITY
 * verdict delegated to moqraw (draft-ietf-moq-transport-18/19 3.1.4-5 +
 * 10.3.1.1-2, -22 6.2.2 + 9.1.1-2). Shares the recording io stubs and the
 * SETUP fixtures of moqtrun_test.c, and the moqrawio recorder backend of
 * moqraw_test.c, in the same unity TU. */

static wired_moqt_hub mtraw_hub;

/* A fresh hub with SESS_A joined over raw QUIC under ALPN alpn. */
static void mtraw_join(const char* alpn) {
  moqtrun_test_reset();
  wired_moqt_init(&mtraw_hub, moqtrun_test_io());
  wired_moqt_on_session_raw(&mtraw_hub, SESS_A, moqtrun_test_proto(alpn));
}

/* SESS_A's client control stream (uni 2) carrying SETUP with opts. */
static void mtraw_setup(const u8* opts, usz opts_len) {
  u8  msg[64];
  usz n = mtctl_uni_ctl(msg, opts, opts_len);
  wired_moqt_on_stream_data(&mtraw_hub, SESS_A, 2, mtctl_span(msg, n), 0);
}

/* Close code of the one io.close_session call, ~0 for none. */
static u64 mtraw_close_code(void) {
  const moqtrun_test_call* c = moqtrun_test_last_kind(11);
  if (moqtrun_test_count_kind(11) != 1 || !c) return ~(u64)0;
  return c->stream_id;
}

/* T-F1, -22 6.2 (-18/-19 3.1): "moqt-NN" is the version negotiation on
 * native QUIC, through the same moqver table as the WT subprotocol. The
 * session is raw and never legacy, so the hub's SETUP goes out on a
 * keep-open uni stream (-22 6.3/6.4.1), never a bidi, its first bytes the
 * SETUP Type 0x2F00 (AF 00, the 1.4.1 varint) that is also the Stream
 * Type. */
static void test_moqtrun_raw_ver_from_alpn(void) {
  static const struct {
    const char* alpn;
    int         ver;
  } rows[] = {
      {"moqt-18", MOQVER_D18},
      {"moqt-19", MOQVER_D19},
      {"moqt-22", MOQVER_D22},
  };
  for (usz i = 0; i < sizeof rows / sizeof rows[0]; i++) {
    mtraw_join(rows[i].alpn);
    const wired_moqtrun_peer* p = &mtraw_hub.peers[0];
    const moqtrun_test_call*  c = moqtrun_test_last_kind(5);
    CHECK(p->in_use && p->ver == rows[i].ver);
    CHECK(p->raw == 1 && p->legacy == 0);
    CHECK(moqtrun_test_count_kind(1) == 0);
    CHECK(moqtrun_test_count_kind(5) == 1);
    CHECK(c && c->payload_len >= 2 && c->payload[0] == 0xAF);
    CHECK(c && c->payload[1] == 0x00);
  }
}

/* A second raw callback for a tracked session sends no second SETUP
 * (-22 6.3: one control stream per peer). */
static void test_moqtrun_raw_duplicate_ignored(void) {
  mtraw_join("moqt-22");
  wired_moqt_on_session_raw(&mtraw_hub, SESS_A, moqtrun_test_proto("moqt-22"));
  CHECK(moqtrun_test_count_kind(5) == 1);
  CHECK(!mtraw_hub.peers[1].in_use);
}

/* PATH "/" (type 0x01) then AUTHORITY "relay:4443" (0x05, delta 4). */
static const u8 mtraw_path_auth[] = {0x01, 0x01, '/', 0x04, 0x0A, 'r', 'e', 'l',
                                     'a',  'y',  ':', '4',  '4',  '4', '3'};

/* T-F2 (REQ-B), -22 6.2.2 "the authority, path-abempty and query are sent
 * in Setup Options": a raw SETUP with PATH and AUTHORITY establishes. */
static void test_moqtrun_raw_path_authority_established(void) {
  mtraw_join("moqt-22");
  mtraw_setup(mtraw_path_auth, sizeof mtraw_path_auth);
  CHECK(moqtrun_test_count_kind(11) == 0);
  CHECK(moqsess_established(&mtraw_hub.peers[0].sess));
}

/* T-F2: the same bytes on a WebTransport session still close
 * INVALID_PATH (-22 9.1.2: PATH "received ... over WebTransport"). */
static void test_moqtrun_raw_same_setup_on_wt_closes(void) {
  wired_moqt_hub* hub = &mtraw_hub;
  mtctl_session_with_setup(
      hub, "moqt-22", mtraw_path_auth, sizeof mtraw_path_auth);
  CHECK(mtraw_close_code() == WIRED_MOQTRUN_CLOSE_INVALID_PATH);
  CHECK(!hub->peers[0].raw);
  CHECK(!moqsess_established(&hub->peers[0].sess));
}

/* T-F3, -22 9.1.2 / 9.1.1: a PATH that is no path-abempty closes
 * MALFORMED_PATH (0x9); an AUTHORITY with an empty host closes
 * MALFORMED_AUTHORITY (0x1A) -- through io.close_session, unestablished. */
static void test_moqtrun_raw_malformed_closes(void) {
  static const u8 bad_path[] = {0x01, 0x03, 'm', 'o', 'q'};
  static const u8 bad_auth[] = {0x05, 0x04, ':', '4', '4', '3'};
  mtraw_join("moqt-19");
  mtraw_setup(bad_path, sizeof bad_path);
  CHECK(mtraw_close_code() == WIRED_MOQTRUN_CLOSE_MALFORMED_PATH);
  CHECK(!moqsess_established(&mtraw_hub.peers[0].sess));
  mtraw_join("moqt-19");
  mtraw_setup(bad_auth, sizeof bad_auth);
  CHECK(mtraw_close_code() == WIRED_MOQTRUN_CLOSE_MALFORMED_AUTHORITY);
}

static int mtraw_refuse(void* ctx, wired_span v) {
  (void)ctx;
  (void)v;
  return 0;
}

/* hub.raw_policy: a hook refusing a well-formed path closes INVALID_PATH
 * (-22 9.1.2 "naming an unsupported path"); zero hooks accept. */
static void test_moqtrun_raw_policy_refuses(void) {
  moqtrun_test_reset();
  wired_moqt_init(&mtraw_hub, moqtrun_test_io());
  mtraw_hub.raw_policy.accept_path = mtraw_refuse;
  wired_moqt_on_session_raw(&mtraw_hub, SESS_A, moqtrun_test_proto("moqt-22"));
  mtraw_setup(mtraw_path_auth, sizeof mtraw_path_auth);
  CHECK(mtraw_close_code() == WIRED_MOQTRUN_CLOSE_INVALID_PATH);
}

/* Review F4: with every peer slot taken, a raw session is closed at once
 * with INTERNAL_ERROR (-22 6.6) instead of waiting for the idle sweep; no
 * SETUP goes to it. */
static void test_moqtrun_raw_full_hub_closes(void) {
  moqtrun_test_reset();
  wired_moqt_init(&mtraw_hub, moqtrun_test_io());
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_SESSIONS; i++)
    wired_moqt_on_session_raw(
        &mtraw_hub, (wired_wt_session*)(usz)(100 + i),
        moqtrun_test_proto("moqt-22"));
  CHECK(moqtrun_test_count_kind(11) == 0);
  wired_moqt_on_session_raw(&mtraw_hub, SESS_A, moqtrun_test_proto("moqt-22"));
  const moqtrun_test_call* c = moqtrun_test_last_kind(11);
  CHECK(mtraw_close_code() == WIRED_MOQTRUN_CLOSE_INTERNAL_ERROR);
  CHECK(c && c->s == SESS_A);
  CHECK(moqtrun_test_count_kind(5) == WIRED_MOQTRUN_MAX_SESSIONS);
}

/* T-F4: every close code the hub can hand io.close_session is a MoQT
 * Session Termination code (-22 12.2: 0x0..0x1B), never a WT/HTTP/3
 * mapped value -- the backend carries it verbatim on raw (CONNECTION_CLOSE
 * 0x1d, RFC 9000 19.19). */
static void test_moqtrun_raw_close_codes_moqt_only(void) {
  static const u32 codes[] = {
      WIRED_MOQTRUN_CLOSE_NO_ERROR,
      WIRED_MOQTRUN_CLOSE_INTERNAL_ERROR,
      WIRED_MOQTRUN_CLOSE_PROTOCOL_VIOLATION,
      WIRED_MOQTRUN_CLOSE_INVALID_REQUEST_ID,
      WIRED_MOQTRUN_CLOSE_INVALID_PATH,
      WIRED_MOQTRUN_CLOSE_MALFORMED_PATH,
      WIRED_MOQTRUN_CLOSE_GOAWAY_TIMEOUT,
      WIRED_MOQTRUN_CLOSE_INVALID_AUTHORITY,
      WIRED_MOQTRUN_CLOSE_MALFORMED_AUTHORITY,
      WIRED_MOQTRUN_CLOSE_TOO_MANY_REQUEST_UPDATES,
  };
  for (usz i = 0; i < sizeof codes / sizeof codes[0]; i++)
    CHECK(codes[i] <= 0x1B);
  CHECK(WIRED_MOQTRUN_CLOSE_MALFORMED_PATH == MOQRAW_CLOSE_MALFORMED_PATH);
  CHECK(
      WIRED_MOQTRUN_CLOSE_MALFORMED_AUTHORITY ==
      MOQRAW_CLOSE_MALFORMED_AUTHORITY);
}

/* GOAWAY's New Session URI to p's session, as decoded from the last
 * control-stream send; n = ~0 when none decodes. */
static wired_span mtraw_goaway_uri(const wired_moqtrun_peer* p) {
  const moqtrun_test_call* c   = moqtrun_test_last_kind(3);
  usz                      off = 0, boff = 0;
  u64                      type;
  wired_span               body;
  moqctl_goaway            g;
  wired_span               none = {0, ~(usz)0};
  if (!c) return none;
  if (moqctl_peek_type(
          wired_span_of(c->payload, c->payload_len), &off, &type, &body) !=
      MOQCTL_OK)
    return none;
  if (moqtrun_goaway_decoder(p->ver)(body, &boff, &g) != MOQCTL_OK) return none;
  return g.new_session_uri;
}

/* Plan open question 5 / K10, -22 9.2 (-18/-19 10.4): the New Session
 * URI "SHOULD use the same scheme as the current URI" and a zero-length
 * one means reuse the current URI -- a raw session gets an empty one,
 * whatever WT locator the app passed; a WT session gets the app's URI. */
static void test_moqtrun_raw_goaway_uri_empty(void) {
  static const u8 uri[] = "https://relay:4443/moq";
  wired_span      u     = wired_span_of(uri, sizeof uri - 1);
  mtraw_join("moqt-22");
  CHECK(wired_moqt_goaway(&mtraw_hub, u, 0) == 1);
  CHECK(mtraw_goaway_uri(&mtraw_hub.peers[0]).n == 0);
  mtctl_session_with_setup(&mtraw_hub, "moqt-22", 0, 0);
  CHECK(wired_moqt_goaway(&mtraw_hub, u, 0) == 1);
  CHECK(mtraw_goaway_uri(&mtraw_hub.peers[0]).n == u.n);
}

static wired_wt_session mtraw_sess;

/* The hub over moqrawio's mux (moqraw_test.c's recorder backend): a raw
 * session's SETUP leaves byte for byte (-22 6.3, no WT signal), a WT
 * session's behind the uni signal 0x54 + session id 4
 * (draft-ietf-webtrans-http3 4.2). */
static void test_moqtrun_raw_via_mux(void) {
  static const u8 wt_head[] = {0x40, 0x54, 0x04, 0xAF, 0x00};
  wired_moqt_io   io        = moqtrun_test_io();
  wired_moqt_io   mux       = moqrawio_io(&mqrw_be);
  io.open_uni_stream        = mux.open_uni_stream;
  io.open_bidi_stream       = mux.open_bidi_stream;
  wired_wt_session_init(&mtraw_sess, 4);
  moqtrun_test_reset();
  wired_moqt_init(&mtraw_hub, io);
  mqrw_is_raw = 1;
  mqrw_calls  = 0;
  wired_moqt_on_session_raw(
      &mtraw_hub, &mtraw_sess, moqtrun_test_proto("moqt-22"));
  CHECK(mqrw_calls == 1);
  CHECK(mqrw_last_n >= 2 && mqrw_last[0] == 0xAF && mqrw_last[1] == 0x00);
  wired_moqt_init(&mtraw_hub, io);
  mqrw_is_raw = 0;
  wired_moqt_on_session(
      &mtraw_hub, &mtraw_sess, wired_span_of(0, 0),
      moqtrun_test_proto("moqt-22"));
  CHECK(mqrw_calls == 2);
  CHECK(mqrw_last_n >= 5 && ct_diffn(mqrw_last, wt_head, 5) == 0);
}

void test_moqtrun_raw(void) {
  test_moqtrun_raw_ver_from_alpn();
  test_moqtrun_raw_duplicate_ignored();
  test_moqtrun_raw_path_authority_established();
  test_moqtrun_raw_same_setup_on_wt_closes();
  test_moqtrun_raw_malformed_closes();
  test_moqtrun_raw_policy_refuses();
  test_moqtrun_raw_full_hub_closes();
  test_moqtrun_raw_close_codes_moqt_only();
  test_moqtrun_raw_goaway_uri_empty();
  test_moqtrun_raw_via_mux();
}
