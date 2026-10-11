#include "test.h"

/* Path n: fd 3, 127.0.0.1:(4000 + n). */
static pathsel_key ps_key(u16 n) {
  pathsel_key k = {3, {0}};
  wired_udp_addr(&k.peer, (u16)(4000 + n), (const u8[4]){127, 0, 0, 1});
  return k;
}

/* RFC 9000 9.6.2: a path is the pair (local socket, peer address). */
static void test_pathsel_key_eq(void) {
  pathsel_key a = ps_key(1), b = ps_key(1);
  CHECK(pathsel_key_eq(&a, &b));
  b.fd = 4; /* same peer, other socket */
  CHECK(!pathsel_key_eq(&a, &b));
  b = ps_key(2); /* other port */
  CHECK(!pathsel_key_eq(&a, &b));
  b = ps_key(1);
  b.peer.addr[15] ^= 1; /* other address */
  CHECK(!pathsel_key_eq(&a, &b));
}

/* A path keeps its own slot, then a free one is taken, then the slot not
 * holding keep is evicted. */
static void test_pathsel_claim_order(void) {
  pathsel       p  = {0};
  pathsel_key   k1 = ps_key(1), k2 = ps_key(2), k3 = ps_key(3);
  pathsel_slot* s1 = pathsel_claim(&p, &k1, &k2);
  pathsel_slot* s2 = pathsel_claim(&p, &k2, &k1);
  CHECK(s1 && s2 && s1 != s2);
  CHECK(s1->in_use && pathsel_key_eq(&s1->key, &k1));
  CHECK(pathsel_claim(&p, &k1, &k2) == s1);
  CHECK(pathsel_find(&p, &k2) == s2);
  CHECK(pathsel_claim(&p, &k3, &k2) == s1); /* k1 evicted, k2 kept */
  CHECK(pathsel_find(&p, &k1) == 0);
  CHECK(pathsel_find(&p, &k3) == s1);
}

/* A probe takes only a free slot, never evicting. */
static void test_pathsel_claim_free(void) {
  pathsel     p  = {0};
  pathsel_key k1 = ps_key(1), k2 = ps_key(2), k3 = ps_key(3);
  CHECK(pathsel_claim_free(&p, &k1) != 0);
  CHECK(pathsel_claim_free(&p, &k2) != 0);
  CHECK(pathsel_claim_free(&p, &k3) == 0);
  CHECK(pathsel_find(&p, &k3) == 0);
}

/* RFC 9000 8.2.3: only matching data validates; the slot is freed; a free
 * slot (stale zero data) never matches. */
static void test_pathsel_match(void) {
  pathsel       p               = {0};
  pathsel_key   k1              = ps_key(1), out;
  u8            zero[PATH_DATA] = {0}, d[PATH_DATA] = {1, 2, 3, 4, 5, 6, 7, 8};
  u8            bad[PATH_DATA] = {1, 2, 3, 4, 5, 6, 7, 9};
  pathsel_slot* s              = pathsel_claim(&p, &k1, &k1);
  bytes_memcpy(s->data, d, PATH_DATA);
  CHECK(pathsel_match(&p, bad, &out) == 0);
  CHECK(pathsel_match(&p, zero, &out) == 0);
  CHECK(pathsel_match(&p, d, &out) == 1);
  CHECK(pathsel_key_eq(&out, &k1));
  CHECK(s->in_use == 0);
  CHECK(pathsel_match(&p, d, &out) == 0); /* answered once */
}

/* RFC 9000 8.2.4: a slot expires at first_ms + timeout, not before. */
static void test_pathsel_expire(void) {
  pathsel       p  = {0};
  pathsel_key   k1 = ps_key(1), out;
  pathsel_slot* s  = pathsel_claim(&p, &k1, &k1);
  s->first_ms      = 100;
  s->last_ms       = 900;
  CHECK(pathsel_expire(&p, 1099, 1000, &out) == 0);
  CHECK(pathsel_expire(&p, 1100, 1000, &out) == 1);
  CHECK(pathsel_key_eq(&out, &k1));
  CHECK(s->in_use == 0);
  CHECK(pathsel_expire(&p, 5000, 1000, &out) == 0);
}

/* RFC 9000 9.4 / RFC 9002 6.2.1: a retransmit is due one PTO after the
 * latest challenge, doubling with every retransmission. */
static void test_pathsel_resend_backoff(void) {
  pathsel       p  = {0};
  pathsel_key   k1 = ps_key(1);
  pathsel_slot* s  = pathsel_claim(&p, &k1, &k1);
  s->last_ms       = 100;
  CHECK(pathsel_resend_due(&p, 199, 100) == 0);
  CHECK(pathsel_resend_due(&p, 200, 100) == s);
  s->tries   = 1;
  s->last_ms = 200;
  CHECK(pathsel_resend_due(&p, 399, 100) == 0);
  CHECK(pathsel_resend_due(&p, 400, 100) == s);
}

/* RFC 9000 8.2.3: after a resend, a response to the earlier challenge
 * still matches. */
static void test_pathsel_match_earlier(void) {
  pathsel       p              = {0};
  pathsel_key   k1             = ps_key(1), out;
  u8            d[PATH_DATA]   = {1, 2, 3, 4, 5, 6, 7, 8};
  u8            bad[PATH_DATA] = {1, 2, 3, 4, 5, 6, 7, 9};
  pathsel_slot* s              = pathsel_claim(&p, &k1, &k1);
  bytes_memcpy(s->prev, d, PATH_DATA);
  bytes_memcpy(s->data, bad, PATH_DATA);
  s->tries = 1;
  CHECK(pathsel_match(&p, d, &out) == 1);
  CHECK(pathsel_key_eq(&out, &k1));
}

void test_pathsel(void) {
  test_pathsel_match_earlier();
  test_pathsel_key_eq();
  test_pathsel_claim_order();
  test_pathsel_claim_free();
  test_pathsel_match();
  test_pathsel_expire();
  test_pathsel_resend_backoff();
}
