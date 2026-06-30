#include "tls/handshake/core/tls/transcript.h"

#include "test.h"

static int tr_digest_eq(const u8 *got, const char *hex) {
  for (usz i = 0; i < QUIC_SHA256_DIGEST; i++) {
    u8 hi = hex[i * 2], lo = hex[i * 2 + 1];
    u8 b = (u8)(((hi <= '9' ? hi - '0' : hi - 'a' + 10) << 4) |
                (lo <= '9' ? lo - '0' : lo - 'a' + 10));
    if (got[i] != b) return 0;
  }
  return 1;
}

/* Empty transcript hashes the empty string (RFC 8446 4.4.1). */
static void test_transcript_empty(void) {
  quic_transcript t;
  u8              d[QUIC_SHA256_DIGEST];
  quic_transcript_init(&t);
  quic_transcript_hash(&t, d);
  CHECK(tr_digest_eq(
      d, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
}

/* One added message hashes to that message's SHA-256. */
static void test_transcript_one(void) {
  quic_transcript t;
  u8              d[QUIC_SHA256_DIGEST];
  quic_transcript_init(&t);
  quic_transcript_add(&t, (const u8 *)"abc", 3);
  quic_transcript_hash(&t, d);
  CHECK(tr_digest_eq(
      d, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
}

/* Cumulative: two messages hash to the concatenation. */
static void test_transcript_two(void) {
  quic_transcript t;
  u8              d[QUIC_SHA256_DIGEST];
  quic_transcript_init(&t);
  quic_transcript_add(&t, (const u8 *)"abc", 3);
  quic_transcript_add(&t, (const u8 *)"def", 3);
  quic_transcript_hash(&t, d);
  CHECK(tr_digest_eq(
      d, "bef57ec7f53a6d40beb640a780a639c83bc29ac8a9816f1fc6c5c6dcd93c4721"));
}

/* Snapshotting must not disturb the running state. */
static void test_transcript_snapshot_nondestructive(void) {
  quic_transcript t;
  u8              d1[QUIC_SHA256_DIGEST], d2[QUIC_SHA256_DIGEST];
  quic_transcript_init(&t);
  quic_transcript_add(&t, (const u8 *)"abc", 3);
  quic_transcript_hash(&t, d1);
  quic_transcript_add(&t, (const u8 *)"def", 3);
  quic_transcript_hash(&t, d2);
  CHECK(tr_digest_eq(
      d1, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
  CHECK(tr_digest_eq(
      d2, "bef57ec7f53a6d40beb640a780a639c83bc29ac8a9816f1fc6c5c6dcd93c4721"));
}

void test_transcript(void) {
  test_transcript_empty();
  test_transcript_one();
  test_transcript_two();
  test_transcript_snapshot_nondestructive();
}
