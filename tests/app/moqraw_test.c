/* Raw-QUIC MoQT: Setup Option policy (moqraw.c, plan T-C1..C5) and the
 * transport-mux io table (moqrawio.c, plan T-D1..D4). PATH/AUTHORITY:
 * draft-ietf-moq-transport-18/19 10.3.1.1-2, -22 9.1.1-2; RFC 3986 3.2/3.3. */

static moqctl_setup mqrw_setup(const char* path, const char* auth) {
  moqctl_setup m = {0};
  m.has_path     = path != 0;
  m.path = wired_span_of((const u8*)path, path ? wired_cstr_len(path) : 0);
  m.has_authority = auth != 0;
  m.authority = wired_span_of((const u8*)auth, auth ? wired_cstr_len(auth) : 0);
  return m;
}

static u32 mqrw_v(int raw, const char* path, const char* auth) {
  moqctl_setup m = mqrw_setup(path, auth);
  return moqraw_setup_verdict(raw, &m, 0);
}

/* T-C1 (R9): path-abempty [?query]. */
static void test_moqraw_path(void) {
  CHECK(mqrw_v(1, 0, 0) == 0);
  CHECK(mqrw_v(1, "", 0) == 0);
  CHECK(mqrw_v(1, "/", 0) == 0);
  CHECK(mqrw_v(1, "/moq?x=1", 0) == 0);
  CHECK(mqrw_v(1, "/a/%2F:@!$&'()*+,;=-._~?q/?", 0) == 0);
  CHECK(mqrw_v(1, "moq", 0) == MOQRAW_CLOSE_MALFORMED_PATH);
  CHECK(mqrw_v(1, "/a b", 0) == MOQRAW_CLOSE_MALFORMED_PATH);
  CHECK(mqrw_v(1, "/a#f", 0) == MOQRAW_CLOSE_MALFORMED_PATH);
  CHECK(mqrw_v(1, "/%zz", 0) == MOQRAW_CLOSE_MALFORMED_PATH);
  CHECK(mqrw_v(1, "/%4", 0) == MOQRAW_CLOSE_MALFORMED_PATH);
  CHECK(mqrw_v(1, "/\xc3\xa9", 0) == MOQRAW_CLOSE_MALFORMED_PATH);
  CHECK(mqrw_v(1, "/\x01", 0) == MOQRAW_CLOSE_MALFORMED_PATH);
}

/* T-C2 (R8): [userinfo "@"] host [":" port]. */
static void test_moqraw_authority(void) {
  CHECK(mqrw_v(1, 0, "relay:4443") == 0);
  CHECK(mqrw_v(1, 0, "[::1]:443") == 0);
  CHECK(mqrw_v(1, 0, "[::1]") == 0);
  CHECK(mqrw_v(1, 0, "a@b") == 0);
  CHECK(mqrw_v(1, 0, "192.0.2.1:65535") == 0);
  CHECK(mqrw_v(1, 0, "relay:") == 0);
  CHECK(mqrw_v(1, 0, ":443") == MOQRAW_CLOSE_MALFORMED_AUTHORITY);
  CHECK(mqrw_v(1, 0, "") == MOQRAW_CLOSE_MALFORMED_AUTHORITY);
  CHECK(mqrw_v(1, 0, "a@") == MOQRAW_CLOSE_MALFORMED_AUTHORITY);
  CHECK(mqrw_v(1, 0, "relay:65536") == MOQRAW_CLOSE_MALFORMED_AUTHORITY);
  CHECK(mqrw_v(1, 0, "relay:99999") == MOQRAW_CLOSE_MALFORMED_AUTHORITY);
  CHECK(mqrw_v(1, 0, "relay:4x") == MOQRAW_CLOSE_MALFORMED_AUTHORITY);
  CHECK(mqrw_v(1, 0, "[::1") == MOQRAW_CLOSE_MALFORMED_AUTHORITY);
  CHECK(mqrw_v(1, 0, "[]") == MOQRAW_CLOSE_MALFORMED_AUTHORITY);
  CHECK(mqrw_v(1, 0, "[::1]x") == MOQRAW_CLOSE_MALFORMED_AUTHORITY);
  CHECK(mqrw_v(1, 0, "a@b@c") == MOQRAW_CLOSE_MALFORMED_AUTHORITY);
  CHECK(mqrw_v(1, 0, "re lay") == MOQRAW_CLOSE_MALFORMED_AUTHORITY);
  CHECK(mqrw_v(1, 0, "relay/x") == MOQRAW_CLOSE_MALFORMED_AUTHORITY);
}

/* T-C3: WebTransport keeps the pre-raw behavior (PATH first). */
static void test_moqraw_wt(void) {
  CHECK(mqrw_v(0, 0, 0) == 0);
  CHECK(mqrw_v(0, "/", 0) == MOQRAW_CLOSE_INVALID_PATH);
  CHECK(mqrw_v(0, 0, "relay:4443") == MOQRAW_CLOSE_INVALID_AUTHORITY);
  CHECK(mqrw_v(0, "/", "relay:4443") == MOQRAW_CLOSE_INVALID_PATH);
}

static int mqrw_refuse(void* ctx, wired_span v) {
  (void)v;
  ++*(int*)ctx;
  return 0;
}

static int mqrw_accept(void* ctx, wired_span v) {
  (void)v;
  ++*(int*)ctx;
  return 1;
}

static u32 mqrw_pol(const char* path, const char* auth, moqraw_policy pol) {
  moqctl_setup m = mqrw_setup(path, auth);
  return moqraw_setup_verdict(1, &m, &pol);
}

/* T-C4: hook refusal, PATH judged first, hooks see only valid values. */
static void test_moqraw_hook(void) {
  int           n   = 0;
  moqraw_policy rp  = {mqrw_refuse, 0, &n};
  moqraw_policy ra  = {0, mqrw_refuse, &n};
  moqraw_policy ok  = {mqrw_accept, mqrw_accept, &n};
  moqraw_policy dft = {0};
  CHECK(mqrw_pol("/", 0, rp) == MOQRAW_CLOSE_INVALID_PATH);
  CHECK(mqrw_pol(0, "h", ra) == MOQRAW_CLOSE_INVALID_AUTHORITY);
  CHECK(
      mqrw_pol("/", "h", (moqraw_policy){mqrw_refuse, mqrw_refuse, &n}) ==
      MOQRAW_CLOSE_INVALID_PATH);
  CHECK(mqrw_pol("/", ":1", rp) == MOQRAW_CLOSE_INVALID_PATH);
  CHECK(mqrw_pol("x", "h", ra) == MOQRAW_CLOSE_MALFORMED_PATH);
  n = 0;
  CHECK(mqrw_pol("bad", 0, rp) == MOQRAW_CLOSE_MALFORMED_PATH);
  CHECK(n == 0);
  CHECK(mqrw_pol("/", "h", ok) == 0);
  CHECK(n == 2);
  CHECK(mqrw_pol("/", "h", dft) == 0);
}

/* T-C5: unknown Setup Options (moqctl_setup_take drops them, duplicates
 * included, -19 10.3 / -22 9.1) never reach the verdict. */
static void test_moqraw_unknown(void) {
  /* type 0x21 (odd, 1 byte) twice via delta 0, then even 0x2a = 5 */
  static const u8 opts[] = {0x21, 0x01, 0x41, 0x00, 0x01, 0x41, 0x09, 0x05};
  usz             at     = 0;
  moqctl_setup    m      = {0};
  CHECK(
      moqctl_setup_take(wired_span_of(opts, sizeof opts), &at, &m) ==
      MOQCTL_OK);
  CHECK(at == sizeof opts);
  CHECK(moqraw_setup_verdict(1, &m, 0) == 0);
  CHECK(moqraw_setup_verdict(0, &m, 0) == 0);
}

/* ---- T-D: io mux over a recorder backend ---- */

static int mqrw_is_raw;
static int mqrw_calls;
static u8  mqrw_last[MOQRAWIO_STAGE_BUF];
static usz mqrw_last_n;

static int mqrw_be_raw(wired_wt_session* s) {
  (void)s;
  return mqrw_is_raw;
}

static i64 mqrw_be_open(wired_wt_session* s, wired_span p) {
  (void)s;
  mqrw_calls++;
  bytes_memcpy(mqrw_last, p.p, p.n);
  mqrw_last_n = p.n;
  return 7;
}

static const moqrawio_backend mqrw_be = {
    mqrw_be_raw, mqrw_be_open, mqrw_be_open, mqrw_be_open};

static int mqrw_last_is(const u8* want, usz n) {
  return mqrw_last_n == n && ct_diffn(mqrw_last, want, n) == 0;
}

static wired_wt_session mqrw_sess;

/* T-D1: WT prefixes signal(0x54/0x41, sid=4); raw sends p as is. */
static void test_moqrawio_prefix(void) {
  static const u8 uni[]  = {0x40, 0x54, 0x04, 0xaa, 0xbb};
  static const u8 bidi[] = {0x40, 0x41, 0x04, 0xaa, 0xbb};
  wired_moqt_io   io     = moqrawio_io(&mqrw_be);
  wired_span      p      = wired_span_of(uni + 3, 2);
  wired_wt_session_init(&mqrw_sess, 4);
  mqrw_is_raw = 0;
  CHECK(io.open_uni_stream(&mqrw_sess, p) == 7);
  CHECK(mqrw_last_is(uni, sizeof uni));
  CHECK(io.send_uni(&mqrw_sess, p) == 7);
  CHECK(mqrw_last_is(uni, sizeof uni));
  CHECK(io.open_bidi_stream(&mqrw_sess, p) == 7);
  CHECK(mqrw_last_is(bidi, sizeof bidi));
  mqrw_is_raw = 1;
  CHECK(io.open_uni_stream(&mqrw_sess, p) == 7);
  CHECK(mqrw_last_is(uni + 3, 2));
  CHECK(io.send_uni(&mqrw_sess, p) == 7);
  CHECK(mqrw_last_is(uni + 3, 2));
  CHECK(io.send_uni2 == 0);
  CHECK(io.stream_send == wired_server_wt_stream_send);
  CHECK(io.stream_stop == wired_server_wt_stream_stop);
}

/* T-D2: raw never opens a bidi stream. */
static void test_moqrawio_bidi_raw(void) {
  wired_moqt_io io = moqrawio_io(&mqrw_be);
  mqrw_is_raw      = 1;
  mqrw_calls       = 0;
  CHECK(io.open_bidi_stream(&mqrw_sess, wired_span_of(0, 0)) == -1);
  CHECK(mqrw_calls == 0);
}

/* T-D3: WT_MAX_DATA remainder on WT, unlimited on raw. */
static void test_moqrawio_budget(void) {
  wired_moqt_io io = moqrawio_io(&mqrw_be);
  mqrw_is_raw      = 0;
  CHECK(io.send_budget(&mqrw_sess) == (usz)-1);
  mqrw_sess.max_data  = 100;
  mqrw_sess.sent_data = 30;
  CHECK(io.send_budget(&mqrw_sess) == 70);
  mqrw_sess.sent_data = 130;
  CHECK(io.send_budget(&mqrw_sess) == 0);
  mqrw_is_raw = 1;
  CHECK(io.send_budget(&mqrw_sess) == (usz)-1);
}

/* T-D4: past the production staging -> -1 on both transports. */
static void test_moqrawio_oversize(void) {
  static u8     big[MOQRAWIO_STAGE_BUF + 1];
  wired_moqt_io io = moqrawio_io(&mqrw_be);
  mqrw_calls       = 0;
  mqrw_is_raw      = 1;
  CHECK(io.send_uni(&mqrw_sess, wired_span_of(big, sizeof big)) == -1);
  CHECK(io.send_uni(&mqrw_sess, wired_span_of(big, sizeof big - 1)) == 7);
  mqrw_is_raw = 0;
  CHECK(io.send_uni(&mqrw_sess, wired_span_of(big, sizeof big - 3)) == -1);
  CHECK(io.send_uni(&mqrw_sess, wired_span_of(big, sizeof big - 4)) == 7);
  CHECK(mqrw_calls == 2);
}

/* wired_moqraw_io: the real srvrun backend fills every op but send_uni2. */
static void test_moqrawio_real(void) {
  wired_moqt_io io = wired_moqraw_io();
  CHECK(io.open_bidi_stream && io.send_uni && io.open_uni_stream);
  CHECK(io.send_budget && io.close_session && io.send_datagram);
  CHECK(io.send_uni2 == 0);
}

void test_moqraw(void) {
  test_moqraw_path();
  test_moqraw_authority();
  test_moqraw_wt();
  test_moqraw_hook();
  test_moqraw_unknown();
  test_moqrawio_prefix();
  test_moqrawio_bidi_raw();
  test_moqrawio_budget();
  test_moqrawio_oversize();
  test_moqrawio_real();
}
