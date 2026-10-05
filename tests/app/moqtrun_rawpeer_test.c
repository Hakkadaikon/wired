/* Raw-QUIC MoQT hub pinned to a REAL peer's bytes (ledger 13-11, plan
 * RawQuic T-L2; .claude/rules/rfc-and-verification-layers.md: a wire
 * feature is not done on self-loopback alone).
 *
 * Source: xquic-moq-interop-client v0.7.0-draft18, image
 * ghcr.io/englishm/moq-interop-runner-xquic-moq-client-draft-18@sha256:
 * 485c0895162b9cec1150b97554e3e98bede8c36172196e730e385935667a196e,
 * run as `RELAY_URL=moqt://relay:4443` against the wired relay on 2026-10-05
 * (6/6 testcases ok); tcpdump on the docker bridge, decrypted with tshark
 * and the relay's --keylog. Every client array below is the stream data of
 * that capture, byte for byte; every want array is what the wired relay
 * sent back and the xquic client accepted.
 *
 * Client ClientHello ALPN extension: protocol list = "moqt-18" only.
 * Client uni stream 2: SETUP 0x2F00 (varint AF 00), Length 0x000E, options
 *   01 00              PATH, empty (-18 10.3.1.1)
 *   04 0A "relay:4443" AUTHORITY (type 5, delta 4)
 * Relay uni stream 3: SETUP, no options: AF 00 00 00.
 * Client bidi 0: PUBLISH_NAMESPACE (0x06) / SUBSCRIBE (0x03). */

static const u8 mtrp_client_alpn[]  = {0x00, 0x08, 0x07, 'm', 'o',
                                       'q',  't',  '-',  '1', '8'};
static const u8 mtrp_client_setup[] = {0xAF, 0x00, 0x00, 0x0E, 0x01, 0x00,
                                       0x04, 0x0A, 'r',  'e',  'l',  'a',
                                       'y',  ':',  '4',  '4',  '4',  '3'};
static const u8 mtrp_want_setup[]   = {0xAF, 0x00, 0x00, 0x00};
/* PUBLISH_NAMESPACE id 0, ns tuple ["moq-test/interop"], no params. */
static const u8 mtrp_client_pubns[] = {
    0x06, 0x00, 0x14, 0x00, 0x01, 0x10, 'm', 'o', 'q', '-', 't', 'e',
    's',  't',  '/',  'i',  'n',  't',  'e', 'r', 'o', 'p', 0x00};
static const u8 mtrp_want_ok[] = {0x07, 0x00, 0x01, 0x00};
/* SUBSCRIBE id 0, ns ["nonexistent/namespace"], track "test-track". */
static const u8 mtrp_client_sub[] = {
    0x03, 0x00, 0x24, 0x00, 0x01, 0x15, 'n', 'o', 'n', 'e', 'x', 'i', 's',
    't',  'e',  'n',  't',  '/',  'n',  'a', 'm', 'e', 's', 'p', 'a', 'c',
    'e',  0x0A, 't',  'e',  's',  't',  '-', 't', 'r', 'a', 'c', 'k', 0x00};
/* REQUEST_ERROR: code 0x10 DOES_NOT_EXIST, retry interval 0, empty reason. */
static const u8 mtrp_want_err[] = {0x05, 0x00, 0x03, 0x10, 0x00, 0x00};

static int mtrp_sent_is(const moqtrun_test_call* c, const u8* w, usz n) {
  return c && c->payload_len == n && ct_diffn(c->payload, w, n) == 0;
}

/* The captured SETUP on uni stream 2 of a fresh moqt-18 raw session. */
static void mtrp_session(void) {
  mtraw_join("moqt-18");
  wired_moqt_on_stream_data(
      &mtraw_hub, SESS_A, 2,
      wired_span_of(mtrp_client_setup, sizeof mtrp_client_setup), 0);
}

/* A captured request on bidi stream 0. */
static void mtrp_request(const u8* b, usz n) {
  wired_moqt_on_stream_data(&mtraw_hub, SESS_A, 0, wired_span_of(b, n), 0);
}

/* RFC 7301 3.1 over the captured ALPN extension: the server picks the raw
 * id it was configured with. */
static void test_moqtrun_rawpeer_alpn(void) {
  wired_span tok = {0, 0};
  CHECK(
      salpn_raw_pick(
          mtrp_client_alpn, sizeof mtrp_client_alpn, "moqt-22 moqt-19 moqt-18",
          &tok) == SALPN_RAW);
  CHECK(tok.n == 7 && ct_diffn(tok.p, (const u8*)"moqt-18", 7) == 0);
}

/* The client's SETUP (empty PATH + AUTHORITY) establishes the raw session,
 * no close; the hub's SETUP left on a uni stream as AF 00 00 00. */
static void test_moqtrun_rawpeer_setup(void) {
  mtrp_session();
  CHECK(moqtrun_test_count_kind(11) == 0);
  CHECK(moqsess_established(&mtraw_hub.peers[0].sess));
  CHECK(mtrp_sent_is(moqtrun_test_last_kind(5), mtrp_want_setup, 4));
}

/* PUBLISH_NAMESPACE answered with REQUEST_OK on the request's stream. */
static void test_moqtrun_rawpeer_publish_namespace(void) {
  mtrp_session();
  mtrp_request(mtrp_client_pubns, sizeof mtrp_client_pubns);
  const moqtrun_test_call* c = moqtrun_test_last_kind(12);
  CHECK(mtrp_sent_is(c, mtrp_want_ok, sizeof mtrp_want_ok));
  CHECK(c && c->stream_id == 0);
}

/* SUBSCRIBE to an unannounced namespace answered REQUEST_ERROR
 * DOES_NOT_EXIST. */
static void test_moqtrun_rawpeer_subscribe_error(void) {
  mtrp_session();
  mtrp_request(mtrp_client_sub, sizeof mtrp_client_sub);
  const moqtrun_test_call* c = moqtrun_test_last_kind(12);
  CHECK(mtrp_sent_is(c, mtrp_want_err, sizeof mtrp_want_err));
  CHECK(c && c->stream_id == 0);
}

void test_moqtrun_rawpeer(void) {
  test_moqtrun_rawpeer_alpn();
  test_moqtrun_rawpeer_setup();
  test_moqtrun_rawpeer_publish_namespace();
  test_moqtrun_rawpeer_subscribe_error();
}
