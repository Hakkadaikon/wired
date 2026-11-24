#include "app/nostr/nip98/nip98.h"

#include "crypto/symmetric/hash/hash/sha256.h"
#include "nostrev_fixtures.h"
#include "test.h"

/* NIP-98 checker and replay cache, against nostr-tools tokens (T2:
 * CONNECT https://hub.example/moq?room=r1; T3/E3: POST
 * https://hub.example/upload with payload = sha256('{"a":1}'); both
 * created_at 1732400000). */

#define N98_T 1732400000ULL

static u8           n98_buf[4096];
static nostrev      n98_ev;
static nip98_replay n98_rc; /* window 60 s */

static wired_span n98_s(const char* s) {
  return wired_span_of((const u8*)s, wired_cstr_len(s));
}

static nip98_req n98_t2_req(void) {
  return (nip98_req){
      .url    = n98_s("https://hub.example/moq?room=r1"),
      .method = n98_s("CONNECT"),
      .now    = N98_T,
      .replay = &n98_rc};
}

static nip98_verdict n98_run(const nip98_req* rq, const char* tok) {
  return nip98_check(rq, n98_s(tok), &n98_ev, n98_buf, sizeof(n98_buf));
}

/* Both token forms of a real nostr-tools token pass; the parsed pubkey is
 * the signer's. */
static void test_nip98_ok_forms(void) {
  nip98_req   rq = n98_t2_req();
  static char lower[sizeof(nostrev_fx_t2)];
  CHECK(n98_run(&rq, nostrev_fx_t2) == NIP98_OK);
  CHECK(n98_ev.pubkey[0] == 0x5c && n98_ev.kind == NIP98_KIND);
  bytes_memcpy(lower, nostrev_fx_t2, sizeof(lower));
  lower[0] = 'n';
  CHECK(n98_run(&rq, lower) == NIP98_OK);
  rq.url    = n98_s("https://hub.example/upload");
  rq.method = n98_s("POST");
  CHECK(n98_run(&rq, nostrev_fx_e3) == NIP98_OK);
  CHECK(n98_run(&rq, nostrev_fx_t3) == NIP98_OK);
}

/* nip98_precheck stops before the signature: a token with a bad
 * signature passes it and fails nip98_check; a cheap failure is the same
 * in both. */
static void test_nip98_precheck_skips_sig(void) {
  nip98_req   rq = n98_t2_req();
  static char bad[sizeof(nostrev_fx_e3)];
  usz         i = sizeof(bad) - 5; /* a hex digit of "sig" */
  rq.url        = n98_s("https://hub.example/upload");
  rq.method     = n98_s("POST");
  bytes_memcpy(bad, nostrev_fx_e3, sizeof(bad));
  bad[i] = bad[i] == '0' ? '1' : '0';
  CHECK(
      nip98_precheck(&rq, n98_s(bad), &n98_ev, n98_buf, sizeof(n98_buf)) ==
      NIP98_OK);
  CHECK(n98_run(&rq, bad) == NIP98_BAD_SIG);
  rq.method = n98_s("GET");
  CHECK(
      nip98_precheck(&rq, n98_s(bad), &n98_ev, n98_buf, sizeof(n98_buf)) ==
      NIP98_BAD_METHOD);
}

/* A pad followed by data ("AA=A") after a valid token is not base64:
 * it must not decode to nothing and let the token through. */
static void test_nip98_pad_then_data(void) {
  nip98_req   rq = n98_t2_req();
  static char t[sizeof(nostrev_fx_t2) + 4];
  usz         n = sizeof(nostrev_fx_t2) - 1;
  bytes_memcpy(t, nostrev_fx_t2, n);
  bytes_memcpy(t + n, "AA=A", 5);
  CHECK(n98_run(&rq, t) == NIP98_MALFORMED);
}

/* Time window boundaries: +-60 s pass, +-61 s fail; a cache built with a
 * 5 s window narrows the check to 5 s. */
static void test_nip98_window(void) {
  static nip98_replay rc5;
  nip98_req           rq = n98_t2_req();
  rq.now                 = N98_T + 60;
  CHECK(n98_run(&rq, nostrev_fx_t2) == NIP98_OK);
  rq.now = N98_T - 60;
  CHECK(n98_run(&rq, nostrev_fx_t2) == NIP98_OK);
  rq.now = N98_T + 61;
  CHECK(n98_run(&rq, nostrev_fx_t2) == NIP98_EXPIRED);
  rq.now = N98_T - 61;
  CHECK(n98_run(&rq, nostrev_fx_t2) == NIP98_EXPIRED);
  nip98_replay_init(&rc5, 5);
  rq.replay = &rc5;
  rq.now    = N98_T + 5;
  CHECK(n98_run(&rq, nostrev_fx_t2) == NIP98_OK);
  rq.now = N98_T + 6;
  CHECK(n98_run(&rq, nostrev_fx_t2) == NIP98_EXPIRED);
}

/* u / method compare byte for byte; kind; payload only with a body hash. */
static void test_nip98_fields(void) {
  nip98_req  rq = n98_t2_req();
  u8         h[32];
  sha256_ctx s;
  rq.url = n98_s("https://hub.example/moq?room=r1/");
  CHECK(n98_run(&rq, nostrev_fx_t2) == NIP98_BAD_U);
  rq.url = n98_s("https://HUB.example/moq?room=r1");
  CHECK(n98_run(&rq, nostrev_fx_t2) == NIP98_BAD_U);
  rq        = n98_t2_req();
  rq.method = n98_s("connect");
  CHECK(n98_run(&rq, nostrev_fx_t2) == NIP98_BAD_METHOD);
  rq     = n98_t2_req();
  rq.now = 1700000000;
  CHECK(n98_run(&rq, nostrev_fx_e1) == NIP98_BAD_KIND);
  sha256_init(&s);
  sha256_update(&s, (const u8*)"{\"a\":1}", 7);
  sha256_final(&s, h);
  rq           = n98_t2_req();
  rq.body_hash = h;
  CHECK(n98_run(&rq, nostrev_fx_t2) == NIP98_BAD_PAYLOAD);
  rq.url    = n98_s("https://hub.example/upload");
  rq.method = n98_s("POST");
  CHECK(n98_run(&rq, nostrev_fx_t3) == NIP98_OK);
  h[0] ^= 1;
  CHECK(n98_run(&rq, nostrev_fx_t3) == NIP98_BAD_PAYLOAD);
}

/* Duplicate / valueless u and method tags are ambiguous: refused before
 * any signature work (these events are unsigned). */
static void test_nip98_tag_shape(void) {
  nip98_req rq = {
      .url = n98_s("u1"), .method = n98_s("GET"), .now = 5, .replay = &n98_rc};
  static char       j[512];
  const char* const tags[] = {
      "[[\"u\",\"u1\"],[\"u\",\"u1\"],[\"method\",\"GET\"]]",
      "[[\"u\"],[\"method\",\"GET\"]]",
      "[[\"method\",\"GET\"]]",
      "[[\"u\",\"u1\"],[\"method\",\"GET\"],[\"method\",\"GET\"]]",
      "[[\"u\",\"u1\"],[\"method\",\"GET\",\"x\"]]",
      "[[\"u\"],[\"u\",\"u1\"],[\"method\",\"GET\"]]",
      "[[\"u\",\"u1\"],[\"method\"]]",
  };
  static const nip98_verdict want[] = {
      NIP98_BAD_U,  NIP98_BAD_U, NIP98_BAD_U,     NIP98_BAD_METHOD,
      NIP98_BAD_ID, NIP98_BAD_U, NIP98_BAD_METHOD};
  for (usz i = 0; i < sizeof(want) / sizeof(want[0]); i++) {
    snprintf(
        j, sizeof(j),
        "{\"id\":\"%064d\",\"pubkey\":\"%064d\",\"created_at\":5,"
        "\"kind\":27235,\"tags\":%s,\"content\":\"\",\"sig\":"
        "\"%0128d\"}",
        0, 0, tags[i], 0);
    CHECK(n98_run(&rq, j) == want[i]);
  }
}

/* Malformed input: garbage, bad base64, empty base64, small buffer; a
 * changed id and a changed sig byte in the real event. */
static void test_nip98_malformed(void) {
  nip98_req   rq = n98_t2_req();
  static char j[sizeof(nostrev_fx_e3)];
  rq.url    = n98_s("https://hub.example/upload");
  rq.method = n98_s("POST");
  CHECK(n98_run(&rq, "") == NIP98_MALFORMED);
  CHECK(n98_run(&rq, "{}") == NIP98_MALFORMED);
  CHECK(n98_run(&rq, "Nostr ") == NIP98_MALFORMED);
  CHECK(n98_run(&rq, "Nostr e30*") == NIP98_MALFORMED);
  CHECK(n98_run(&rq, "Nostr e30") == NIP98_MALFORMED);
  CHECK(
      nip98_check(&rq, n98_s(nostrev_fx_t3), &n98_ev, n98_buf, 200) ==
      NIP98_MALFORMED);
  bytes_memcpy(j, nostrev_fx_e3, sizeof(j));
  for (usz i = 0; i + 6 < sizeof(j); i++) {
    if (bytes_span_eq(
            wired_span_of((const u8*)j + i, 6),
            wired_span_of((const u8*)"\"id\":\"", 6))) {
      j[i + 6] = j[i + 6] == '0' ? '1' : '0'; /* first id digit */
    }
  }
  CHECK(n98_run(&rq, j) == NIP98_BAD_ID);
  bytes_memcpy(j, nostrev_fx_e3, sizeof(j));
  j[sizeof(j) - 4] = j[sizeof(j) - 4] == '0' ? '1' : '0';
  CHECK(n98_run(&rq, j) == NIP98_BAD_SIG);
}

/* nip98_check never admits: the caller authorises the verified pubkey,
 * then admits the id. A second use is SEEN; a token whose signature
 * failed was never admitted, so the valid one with the same id passes. */
static void test_nip98_replay_check(void) {
  static nip98_replay rc;
  nip98_req           rq = n98_t2_req();
  static char         j[sizeof(nostrev_fx_e3)];
  nip98_replay_init(&rc, 0);
  rq.replay = &rc;
  CHECK(n98_run(&rq, nostrev_fx_t2) == NIP98_OK);
  CHECK(n98_run(&rq, nostrev_fx_t2) == NIP98_OK);
  CHECK(
      nip98_replay_admit(&rc, n98_ev.id, n98_ev.created_at, rq.now) ==
      NIP98_REPLAY_OK);
  CHECK(n98_run(&rq, nostrev_fx_t2) == NIP98_OK);
  CHECK(
      nip98_replay_admit(&rc, n98_ev.id, n98_ev.created_at, rq.now) ==
      NIP98_REPLAY_SEEN);
  rq.url    = n98_s("https://hub.example/upload");
  rq.method = n98_s("POST");
  bytes_memcpy(j, nostrev_fx_e3, sizeof(j));
  j[sizeof(j) - 4] = j[sizeof(j) - 4] == '0' ? '1' : '0';
  CHECK(n98_run(&rq, j) == NIP98_BAD_SIG);
  CHECK(n98_run(&rq, nostrev_fx_e3) == NIP98_OK);
  CHECK(
      nip98_replay_admit(&rc, n98_ev.id, n98_ev.created_at, rq.now) ==
      NIP98_REPLAY_OK);
}

/* Replay cache (window 10 s): an id is live until created_at + window
 * inclusive; full refuses without evicting; expired slots are reused. */
static void test_nip98_replay_cache(void) {
  static nip98_replay rc;
  u8                  id[32] = {0};
  nip98_replay_init(&rc, 10);
  CHECK(rc.window == 10);
  CHECK(nip98_replay_admit(&rc, id, 10, 10) == NIP98_REPLAY_OK);
  CHECK(nip98_replay_admit(&rc, id, 10, 20) == NIP98_REPLAY_SEEN);
  CHECK(nip98_replay_admit(&rc, id, 11, 21) == NIP98_REPLAY_OK);
  for (usz i = 1; i < NIP98_REPLAY_CAP; i++) {
    id[0] = (u8)i;
    id[1] = (u8)(i >> 8);
    CHECK(nip98_replay_admit(&rc, id, 20 + i, 21) == NIP98_REPLAY_OK);
  }
  id[2] = 1;
  CHECK(nip98_replay_admit(&rc, id, 21, 21) == NIP98_REPLAY_FULL);
  CHECK(nip98_replay_admit(&rc, id, 30, 31) == NIP98_REPLAY_OK);
  CHECK(nip98_replay_admit(&rc, id, 30, 31) == NIP98_REPLAY_SEEN);
}

/* created_at + window saturates instead of wrapping (a wrapped expiry
 * would make the entry dead at once and the token replayable); window 0
 * means the 60 s default. */
static void test_nip98_replay_saturate(void) {
  static nip98_replay rc;
  u8                  id[32] = {7};
  u64                 c      = ~0ULL - 5;
  nip98_replay_init(&rc, 0);
  CHECK(rc.window == NIP98_WINDOW_DEFAULT);
  CHECK(nip98_replay_admit(&rc, id, c, c) == NIP98_REPLAY_OK);
  CHECK(nip98_replay_admit(&rc, id, c, ~0ULL) == NIP98_REPLAY_SEEN);
}

/* The NIP-98 "Request Flow" example header (unpadded base64), verbatim
 * from nips/98.md. Its id is not the hash of its event (nostr-tools'
 * getEventHash disagrees too), so every field check passes and the id
 * check rejects it. */
static const char n98_spec_header[] =
    "Nostr "
    "eyJpZCI6ImZlOTY0ZTc1ODkwMzM2MGYyOGQ4NDI0ZDA5MmRhODQ5NGVkMjA3Y2Jh"
    "ODIzMTEwYmUzYTU3ZGZlNGI1Nzg3MzQiLCJwdWJrZXkiOiI2M2ZlNjMxOGRjNTg1"
    "ODNjZmUxNjgxMGY4NmRkMDllMThiZmQ3NmFhYmMyNGEwMDgxY2UyODU2ZjMzMDUw"
    "NGVkIiwiY29udGVudCI6IiIsImtpbmQiOjI3MjM1LCJjcmVhdGVkX2F0IjoxNjgy"
    "MzI3ODUyLCJ0YWdzIjpbWyJ1IiwiaHR0cHM6Ly9hcGkuc25vcnQuc29jaWFsL2Fw"
    "aS92MS9uNXNwL2xpc3QiXSxbIm1ldGhvZCIsIkdFVCJdXSwic2lnIjoiNWVkOWQ4"
    "ZWM5NThiYzg1NGY5OTdiZGMyNGFjMzM3ZDAwNWFmMzcyMzI0NzQ3ZWZlNGEwMGUy"
    "NGY0YzMwNDM3ZmY0ZGQ4MzA4Njg0YmVkNDY3ZDlkNmJlM2U1YTUxN2JiNDNiMTcz"
    "MmNjN2QzMzk0OWEzYWFmODY3MDVjMjIxODQifQ";

static void test_nip98_spec_example(void) {
  nip98_req rq = {
      .url    = n98_s("https://api.snort.social/api/v1/n5sp/list"),
      .method = n98_s("GET"),
      .now    = 1682327852,
      .replay = &n98_rc};
  CHECK(n98_run(&rq, n98_spec_header) == NIP98_BAD_ID);
  CHECK(n98_ev.kind == NIP98_KIND && n98_ev.created_at == 1682327852ULL);
  rq.method = n98_s("POST");
  CHECK(n98_run(&rq, n98_spec_header) == NIP98_BAD_METHOD);
}

void test_nip98(void) {
  test_nip98_precheck_skips_sig();
  nip98_replay_init(&n98_rc, 0);
  test_nip98_ok_forms();
  test_nip98_pad_then_data();
  test_nip98_window();
  test_nip98_fields();
  test_nip98_tag_shape();
  test_nip98_malformed();
  test_nip98_replay_check();
  test_nip98_replay_cache();
  test_nip98_replay_saturate();
  test_nip98_spec_example();
}
