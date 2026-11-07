/* draft-ietf-moq-transport-23 9.4.1 / 9.4.2 REQUEST_ERROR Error Details:
 * Key-Value-Pairs (8.3) to the end of the message, REDIRECT (0x01) and
 * UNSUPPORTED_PROPERTY (0x02). Goldens are hand-derived vi64 bytes. */

static int mced_take(const u8* b, usz n, moqctl_request_error* e) {
  usz off = 0;
  return moqctl_request_error_take_v(MOQVER_D23, wired_span_of(b, n), &off, e);
}

static int mced_bytes_eq(wired_span a, const u8* p, usz n) {
  int eq = a.n == n;
  for (usz i = 0; eq && i < n; i++) {
    eq = a.p[i] == p[i];
  }
  return eq;
}

static int mced_span_eq(wired_span a, wired_span b) {
  return mced_bytes_eq(a, b.p, b.n);
}

/* Code 0x34 REDIRECT, Retry 0, empty Reason, then REDIRECT (Delta 1,
 * Length 6): Connect URI Length 0, Namespace {"a"}, Track Name "b". */
static const u8 mced_redirect[] = {0x34, 0x00, 0x00, 0x01, 0x06, 0x00,
                                   0x01, 0x01, 'a',  0x01, 'b'};

/* Code 0x33 UNSUPPORTED_EXTENSION, then UNSUPPORTED_PROPERTY 0x4000
 * (Delta 2; vi64 110 + 21 bits: C0 40 00) and 0x4001 (Delta 0). */
static const u8 mced_unsupp[] = {0x33, 0x00, 0x00, 0x02, 0xC0, 0x40,
                                 0x00, 0x00, 0xC0, 0x40, 0x01};

static void test_mced_golden_take(void) {
  moqctl_request_error e;
  CHECK(mced_take(mced_redirect, sizeof mced_redirect, &e) == MOQCTL_OK);
  CHECK(e.error_code == MOQCTL_ERR_REDIRECT && e.has_redirect);
  CHECK(e.redirect.connect_uri.n == 0 && e.redirect.track_namespace.n == 1);
  CHECK(mced_span_eq(e.redirect.track_name, wired_span_of((const u8*)"b", 1)));
  CHECK(mced_take(mced_unsupp, sizeof mced_unsupp, &e) == MOQCTL_OK);
  CHECK(e.n_unsupported == 2 && !e.has_redirect);
  CHECK(e.unsupported[0] == 0x4000 && e.unsupported[1] == 0x4001);
}

/* Encoding the decoded goldens gives their bytes back. */
static void test_mced_golden_put(void) {
  moqctl_request_error e;
  u8                   out[64];
  usz                  n = 0;
  CHECK(mced_take(mced_redirect, sizeof mced_redirect, &e) == MOQCTL_OK);
  CHECK(moqctl_request_error_encode23(wired_mspan_of(out, sizeof out), &n, &e));
  CHECK(mced_bytes_eq(wired_span_of(out, n), mced_redirect, n));
  CHECK(n == sizeof mced_redirect);
  n = 0;
  CHECK(mced_take(mced_unsupp, sizeof mced_unsupp, &e) == MOQCTL_OK);
  CHECK(moqctl_request_error_encode23(wired_mspan_of(out, sizeof out), &n, &e));
  CHECK(n == sizeof mced_unsupp);
  CHECK(mced_bytes_eq(wired_span_of(out, n), mced_unsupp, n));
}

/* xorshift64: a fixed sequence for the round-trip cases. */
static u64 mced_rng(u64* s) {
  *s ^= *s << 13;
  *s ^= *s >> 7;
  *s ^= *s << 17;
  return *s;
}

static u8 mced_pool[256];

/* A random REQUEST_ERROR: REDIRECT with a Redirect, UNSUPPORTED_EXTENSION
 * with 0..MOQCTL_MAX_UNSUPP Types, or another code with neither. */
static void mced_random(u64* s, moqctl_request_error* e) {
  static const u64 codes[] = {
      MOQCTL_ERR_REDIRECT, MOQCTL_ERR_UNSUPPORTED_EXTENSION, 0x9, 0xA};
  *e                            = (moqctl_request_error){0};
  e->error_code                 = codes[mced_rng(s) % 4];
  e->retry_interval             = mced_rng(s) >> (mced_rng(s) % 64);
  e->reason                     = wired_span_of(mced_pool, mced_rng(s) % 40);
  e->has_redirect               = e->error_code == MOQCTL_ERR_REDIRECT;
  e->redirect.connect_uri       = wired_span_of(mced_pool, mced_rng(s) % 30);
  e->redirect.track_namespace.n = 1 + mced_rng(s) % 3;
  e->redirect.track_namespace.fields[0] = wired_span_of(mced_pool, 1);
  e->redirect.track_namespace.fields[1] = wired_span_of(mced_pool + 1, 7);
  e->redirect.track_namespace.fields[2] = wired_span_of(mced_pool + 8, 200);
  e->redirect.track_name = wired_span_of(mced_pool, mced_rng(s) % 150);
  e->n_unsupported       = (u8)(mced_rng(s) % (MOQCTL_MAX_UNSUPP + 1));
  for (usz i = 0; i < e->n_unsupported; i++) {
    e->unsupported[i] = 0x4000 + mced_rng(s) % 0x4000;
  }
}

static int mced_ns_eq(const moqctl_ns* a, const moqctl_ns* b) {
  int eq = a->n == b->n;
  for (usz i = 0; eq && i < a->n; i++) {
    eq = mced_span_eq(a->fields[i], b->fields[i]);
  }
  return eq;
}

static int mced_redirect_eq(
    const moqctl_redirect* a, const moqctl_redirect* b) {
  return mced_span_eq(a->connect_uri, b->connect_uri) &&
         mced_ns_eq(&a->track_namespace, &b->track_namespace) &&
         mced_span_eq(a->track_name, b->track_name);
}

/* What survives the wire: the redirect with REDIRECT only, the Types
 * with UNSUPPORTED_EXTENSION only. */
static int mced_eq(
    const moqctl_request_error* a, const moqctl_request_error* b) {
  int unsupp = a->error_code == MOQCTL_ERR_UNSUPPORTED_EXTENSION;
  int eq = a->error_code == b->error_code &&
           a->retry_interval == b->retry_interval &&
           mced_span_eq(a->reason, b->reason) &&
           a->has_redirect == b->has_redirect &&
           (!a->has_redirect || mced_redirect_eq(&a->redirect, &b->redirect)) &&
           b->n_unsupported == (unsupp ? a->n_unsupported : 0);
  for (usz i = 0; eq && i < b->n_unsupported; i++) {
    eq = a->unsupported[i] == b->unsupported[i];
  }
  return eq;
}

/* Property: decode(encode23(e)) == e over 2000 random REQUEST_ERRORs,
 * and the decode consumes exactly the encoded bytes. */
static void test_mced_roundtrip_property(void) {
  u64 seed = 0x9E3779B97F4A7C15ULL;
  int ok   = 1;
  for (usz i = 0; i < 256; i++) {
    mced_pool[i] = (u8)('a' + i % 26);
  }
  for (int i = 0; i < 2000 && ok; i++) {
    moqctl_request_error e, got;
    u8                   out[1024];
    usz                  n = 0, off = 0;
    mced_random(&seed, &e);
    ok = moqctl_request_error_encode23(
             wired_mspan_of(out, sizeof out), &n, &e) &&
         moqctl_request_error_take_v(
             MOQVER_D23, wired_span_of(out, n), &off, &got) == MOQCTL_OK &&
         off == n && mced_eq(&e, &got);
  }
  CHECK(ok);
}

/* Malformed Error Details and the code each is rejected with. */
static void test_mced_rejects(void) {
  /* REDIRECT with no REDIRECT detail: MALFORMED_MESSAGE (9.4.2.1) */
  static const u8 no_detail[] = {0x34, 0x00, 0x00};
  /* REDIRECT with only an UNSUPPORTED_PROPERTY */
  static const u8 wrong_detail[] = {0x34, 0x00, 0x00, 0x02, 0x05};
  /* Delta Type 2^64-2 (9-byte vi64), then Delta 2: past 2^64-1 */
  static const u8 delta[] = {0x33, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                             0xFF, 0xFF, 0xFF, 0xFE, 0x00, 0x02, 0x00};
  /* odd Type 3 of Length 65536 (C1 00 00) */
  static const u8 len[] = {0x00, 0x00, 0x00, 0x03, 0xC1, 0x00, 0x00};
  /* odd Type 3 of Length 5 with one byte left */
  static const u8 cut[] = {0x00, 0x00, 0x00, 0x03, 0x05, 'a'};
  /* REDIRECT value with one byte past the Redirect */
  static const u8 trail[] = {0x34, 0x00, 0x00, 0x01, 0x07, 0x00,
                             0x01, 0x01, 'a',  0x01, 'b',  0xFF};
  /* REDIRECT value cut inside the Namespace */
  static const u8 short_v[] = {0x34, 0x00, 0x00, 0x01, 0x03, 0x00, 0x01, 0x01};
  moqctl_request_error e;
  CHECK(mced_take(no_detail, sizeof no_detail, &e) == MOQCTL_VIOLATION);
  CHECK(mced_take(wrong_detail, sizeof wrong_detail, &e) == MOQCTL_VIOLATION);
  CHECK(mced_take(delta, sizeof delta, &e) == MOQCTL_R_DELTA);
  CHECK(mced_take(len, sizeof len, &e) == MOQCTL_R_FIELD_LEN);
  CHECK(mced_take(cut, sizeof cut, &e) == MOQCTL_VIOLATION);
  CHECK(mced_take(trail, sizeof trail, &e) == MOQCTL_PARAMS_KVFMT);
  CHECK(mced_take(short_v, sizeof short_v, &e) == MOQCTL_PARAMS_KVFMT);
}

/* 9.4.2: unknown Types are ignored, duplicates included (grease 0x9D,
 * vi64 80 9D, twice); a known Type with a code it is not defined for is
 * ignored; a second REDIRECT is ignored (the first wins); past
 * MOQCTL_MAX_UNSUPP Types only the first are kept. */
static void test_mced_ignored(void) {
  static const u8 grease[] = {0x00, 0x00, 0x00, 0x80, 0x9D, 0x00, 0x00, 0x00};
  static const u8 redir_on_x[]    = {0x09, 0x00, 0x00, 0x01, 0x06, 0x00,
                                     0x01, 0x01, 'a',  0x01, 'b'};
  static const u8 unsupp_on_x[]   = {0x09, 0x00, 0x00, 0x02, 0x05};
  static const u8 two_redirects[] = {0x34, 0x00, 0x00, 0x01, 0x06, 0x00, 0x01,
                                     0x01, 'a',  0x01, 'b',  0x00, 0x06, 0x00,
                                     0x01, 0x01, 'c',  0x01, 'd'};
  u8              many[32]        = {0x33, 0x00, 0x00, 0x02, 0x01};
  usz             n               = 5;
  moqctl_request_error e;
  CHECK(mced_take(grease, sizeof grease, &e) == MOQCTL_OK);
  CHECK(e.error_code == 0 && !e.has_redirect && e.n_unsupported == 0);
  CHECK(mced_take(redir_on_x, sizeof redir_on_x, &e) == MOQCTL_OK);
  CHECK(!e.has_redirect);
  CHECK(mced_take(unsupp_on_x, sizeof unsupp_on_x, &e) == MOQCTL_OK);
  CHECK(e.n_unsupported == 0);
  CHECK(mced_take(two_redirects, sizeof two_redirects, &e) == MOQCTL_OK);
  CHECK(e.has_redirect && e.redirect.track_name.p[0] == 'b');
  for (u8 i = 2; i <= MOQCTL_MAX_UNSUPP + 1; i++) {
    many[n++] = 0x00; /* Delta 0: Type 2 again */
    many[n++] = i;
  }
  CHECK(mced_take(many, n, &e) == MOQCTL_OK);
  CHECK(e.n_unsupported == MOQCTL_MAX_UNSUPP);
  CHECK(e.unsupported[0] == 1 && e.unsupported[7] == 8);
}

/* Before draft-23 the Redirect stays the positional struct: the same
 * bytes decode as such under draft-22 and are not Error Details. */
static void test_mced_d22_positional(void) {
  static const u8 pos[] = {0x34, 0x00, 0x00, 0x00, 0x01, 0x01, 'a', 0x01, 'b'};
  moqctl_request_error e;
  usz                  off = 0;
  CHECK(
      moqctl_request_error_take_v(
          MOQVER_D22, wired_span_of(pos, sizeof pos), &off, &e) == MOQCTL_OK);
  CHECK(e.has_redirect && e.redirect.track_name.p[0] == 'b');
  CHECK(mced_take(pos, sizeof pos, &e) != MOQCTL_OK);
}

void test_moqctl_errdet(void) {
  test_mced_golden_take();
  test_mced_golden_put();
  test_mced_roundtrip_property();
  test_mced_rejects();
  test_mced_ignored();
  test_mced_d22_positional();
}
