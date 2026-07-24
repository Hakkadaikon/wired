#include "test.h"

static quic_ticket tf_sample_ticket(void) {
  quic_ticket t;
  for (usz i = 0; i < QUIC_TICKET_SECRET_LEN; i++) t.secret[i] = (u8)i;
  t.issued_at     = 1000000ULL;
  t.lifetime_secs = 7200;
  t.age_add       = 0xAAAAAAAAu;
  return t;
}

/* (a) obfuscated_ticket_age round-trips: obfuscate then recover restores the
 * original claimed age (RFC 8446 4.2.11.1, mod 2^32 arithmetic). */
static void test_tf_age_roundtrip(void) {
  u32 real_age_ms = 4200;
  u32 age_add     = 0xAAAAAAAAu;
  u32 obfuscated  = real_age_ms + age_add; /* client side, mod 2^32 */
  CHECK(quic_ticket_real_age_ms(obfuscated, age_add) == real_age_ms);
}

/* (a) recovery also works across the u32 wraparound boundary. */
static void test_tf_age_roundtrip_wraps(void) {
  u32 real_age_ms = 10;
  u32 age_add     = 0xFFFFFFF0u;
  u32 obfuscated  = real_age_ms + age_add; /* wraps past 2^32 */
  CHECK(quic_ticket_real_age_ms(obfuscated, age_add) == real_age_ms);
}

/* (b) claimed age matches the server's measured age within the freshness
 * window -> 0-RTT allowed. */
static void test_tf_fresh_within_window(void) {
  quic_ticket t          = tf_sample_ticket();
  u64         now_secs   = t.issued_at + 3; /* 3s since issuance */
  u32         claimed_ms = 3 * 1000;
  u32         obfuscated = claimed_ms + t.age_add;
  CHECK(quic_ticket_freshness_ok(&t, obfuscated, now_secs) == 1);
}

/* (c) claimed age far off from the server's measured age -> 0-RTT rejected,
 * but this is a policy decision the caller downgrades to 1-RTT with, not a
 * connection failure (RFC 8446 4.2.10) -- verified at the sdrv layer. */
static void test_tf_stale_age_rejected(void) {
  quic_ticket t          = tf_sample_ticket();
  u64         now_secs   = t.issued_at + 3;
  u32         claimed_ms = 3600 * 1000; /* claims 1h old, server sees 3s */
  u32         obfuscated = claimed_ms + t.age_add;
  CHECK(quic_ticket_freshness_ok(&t, obfuscated, now_secs) == 0);
}

/* (c) boundary: claimed age fixed at 0s, server-measured age exactly at the
 * window is accepted, one second past it is rejected. */
static void test_tf_window_boundary(void) {
  quic_ticket t          = tf_sample_ticket();
  u32         obfuscated = 0 + t.age_add; /* claims 0s old */
  u64         now_in     = t.issued_at + QUIC_TICKET_FRESHNESS_WINDOW_SECS;
  u64         now_out    = now_in + 1;
  CHECK(quic_ticket_freshness_ok(&t, obfuscated, now_in) == 1);
  CHECK(quic_ticket_freshness_ok(&t, obfuscated, now_out) == 0);
}

/* (d) ticket_lifetime exceeded rejects 0-RTT even with a perfectly fresh
 * claimed age. */
static void test_tf_lifetime_exceeded_rejected(void) {
  quic_ticket t          = tf_sample_ticket();
  u64         now_secs   = t.issued_at + t.lifetime_secs + 1;
  u32         claimed_ms = (u32)t.lifetime_secs * 1000 + 1000;
  u32         obfuscated = claimed_ms + t.age_add;
  CHECK(quic_ticket_freshness_ok(&t, obfuscated, now_secs) == 0);
}

void test_ticketfreshness(void) {
  test_tf_age_roundtrip();
  test_tf_age_roundtrip_wraps();
  test_tf_fresh_within_window();
  test_tf_stale_age_rejected();
  test_tf_window_boundary();
  test_tf_lifetime_exceeded_rejected();
}
