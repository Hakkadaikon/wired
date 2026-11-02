#include "app/http3/server/srvkeys/srvkeys.h"

#include "app/http3/server/srvloop/respond.h"
#include "common/bytes/util/ct.h"
#include "test.h"

/* @file
 * The process-wide ticket / Retry-token seeds come from the CSPRNG, not
 * from bytes compiled into the binary: anyone holding the binary could
 * otherwise forge session tickets (RFC 8446 4.6.1) and Retry tokens
 * (RFC 9000 8.1.3). */

/* The ASCII seed the binary used to carry for tickets ("wired-tkt-key-00"
 * "wired-tkt-key-01"). */
static const u8 g_srvkeys_old_ticket[32] = {
    0x77, 0x69, 0x72, 0x65, 0x64, 0x2d, 0x74, 0x6b, 0x74, 0x2d, 0x6b,
    0x65, 0x79, 0x2d, 0x30, 0x30, 0x77, 0x69, 0x72, 0x65, 0x64, 0x2d,
    0x74, 0x6b, 0x74, 0x2d, 0x6b, 0x65, 0x79, 0x2d, 0x30, 0x31};

static int srvkeys_test_all_zero(const u8* p) {
  static const u8 zero[SRVKEYS_LEN] = {0};
  return ct_diffn(p, zero, SRVKEYS_LEN) == 0;
}

/* Ready, nonzero, not the old constant, and ticket != retry. */
static void test_srvkeys_random_and_distinct(void) {
  CHECK(srvkeys_ready() == 1);
  CHECK(!srvkeys_test_all_zero(srvkeys_ticket()));
  CHECK(!srvkeys_test_all_zero(srvkeys_retry()));
  CHECK(ct_diffn(srvkeys_ticket(), g_srvkeys_old_ticket, SRVKEYS_LEN) != 0);
  CHECK(ct_diffn(srvkeys_ticket(), srvkeys_retry(), SRVKEYS_LEN) != 0);
  CHECK(ct_diffn(srvkeys_newtoken(), srvkeys_retry(), SRVKEYS_LEN) != 0);
  CHECK(ct_diffn(srvkeys_newtoken(), srvkeys_ticket(), SRVKEYS_LEN) != 0);
}

/* Drawn once: later reads see the same bytes (a ticket sealed early opens
 * later in the same process). */
static void test_srvkeys_stable(void) {
  u8 first[SRVKEYS_LEN];
  for (usz i = 0; i < SRVKEYS_LEN; i++) {
    first[i] = srvkeys_ticket()[i];
  }
  CHECK(srvkeys_ready() == 1);
  CHECK(ct_diffn(srvkeys_ticket(), first, SRVKEYS_LEN) == 0);
}

/* The ticket seed an app hands to wired_srvboot_id.ticket_key is this
 * module's draw, so tickets the server seals (respond.c) open under it. */
static void test_srvkeys_ticket_accessor(void) {
  CHECK(
      ct_diffn(wired_srvloop_ticket_key(), srvkeys_ticket(), SRVKEYS_LEN) == 0);
}

static void srvkeys_test_seed(u8 seed[SRVKEYS_LEN], u8 base) {
  for (usz i = 0; i < SRVKEYS_LEN; i++) {
    seed[i] = (u8)(base + i);
  }
}

/* RFC 9000 8.1.3: an app-supplied token seed makes the Retry seed and the
 * NEW_TOKEN key a pure function of it, so a restarted server, or another
 * one behind the same address, given the same seed validates the tokens
 * this one issued. Neither key is the seed itself (a seed also reused as
 * ticket_key must not equal a ticket key), and the two differ. The drawn
 * keys are restored after, so later tests see the process default. */
static void test_srvkeys_token_key_settable(void) {
  u8 a[SRVKEYS_LEN], b[SRVKEYS_LEN], rt[SRVKEYS_LEN], nt[SRVKEYS_LEN];
  u8 saved[2][SRVKEYS_LEN];
  bytes_memcpy(saved[0], g_srvkeys[1], SRVKEYS_LEN);
  bytes_memcpy(saved[1], g_srvkeys[2], SRVKEYS_LEN);
  srvkeys_test_seed(a, 0x30);
  srvkeys_test_seed(b, 0x60);
  CHECK(wired_srvkeys_set_token_key(a) == 1);
  CHECK(ct_diffn(srvkeys_retry(), a, SRVKEYS_LEN) != 0);
  CHECK(ct_diffn(srvkeys_newtoken(), a, SRVKEYS_LEN) != 0);
  CHECK(ct_diffn(srvkeys_newtoken(), srvkeys_retry(), SRVKEYS_LEN) != 0);
  bytes_memcpy(rt, srvkeys_retry(), SRVKEYS_LEN);
  bytes_memcpy(nt, srvkeys_newtoken(), SRVKEYS_LEN);
  CHECK(wired_srvkeys_set_token_key(b) == 1);
  CHECK(ct_diffn(srvkeys_retry(), rt, SRVKEYS_LEN) != 0);
  CHECK(ct_diffn(srvkeys_newtoken(), nt, SRVKEYS_LEN) != 0);
  CHECK(wired_srvkeys_set_token_key(a) == 1);
  CHECK(ct_diffn(srvkeys_retry(), rt, SRVKEYS_LEN) == 0);
  CHECK(ct_diffn(srvkeys_newtoken(), nt, SRVKEYS_LEN) == 0);
  bytes_memcpy(g_srvkeys[1], saved[0], SRVKEYS_LEN);
  bytes_memcpy(g_srvkeys[2], saved[1], SRVKEYS_LEN);
}

/* Known answer: for seed 0x30..0x4f the Retry seed is HMAC-SHA256(seed,
 * "wired retry key") and the NEW_TOKEN key HMAC-SHA256(seed, "wired newtoken
 * key"), both computed independently with Python's hmac/hashlib. Pins the
 * derivation so a restarted or sibling server built from another release
 * still derives the same keys from the same seed. */
static void test_srvkeys_token_key_known_answer(void) {
  static const u8 want_rt[SRVKEYS_LEN] = {
      0x8a, 0xe9, 0x2d, 0x25, 0x13, 0x4a, 0xfb, 0x14, 0x41, 0xf4, 0x18,
      0x6c, 0x5e, 0x9f, 0xa9, 0xe2, 0x4e, 0x7f, 0x8f, 0xce, 0xf9, 0xde,
      0x34, 0x00, 0xa0, 0xcb, 0x43, 0xdd, 0x2f, 0xb8, 0x61, 0xaa};
  static const u8 want_nt[SRVKEYS_LEN] = {
      0x72, 0xac, 0x71, 0x1b, 0xeb, 0x3e, 0xef, 0x16, 0x49, 0x51, 0x3c,
      0xe4, 0x1d, 0x3f, 0x25, 0x33, 0x67, 0x0f, 0xea, 0x19, 0x38, 0xfe,
      0x8d, 0x75, 0x36, 0xf9, 0x72, 0x29, 0xcd, 0x76, 0x4e, 0x29};
  u8 seed[SRVKEYS_LEN], saved[2][SRVKEYS_LEN];
  bytes_memcpy(saved[0], g_srvkeys[1], SRVKEYS_LEN);
  bytes_memcpy(saved[1], g_srvkeys[2], SRVKEYS_LEN);
  srvkeys_test_seed(seed, 0x30);
  CHECK(wired_srvkeys_set_token_key(seed) == 1);
  CHECK(ct_diffn(srvkeys_retry(), want_rt, SRVKEYS_LEN) == 0);
  CHECK(ct_diffn(srvkeys_newtoken(), want_nt, SRVKEYS_LEN) == 0);
  bytes_memcpy(g_srvkeys[1], saved[0], SRVKEYS_LEN);
  bytes_memcpy(g_srvkeys[2], saved[1], SRVKEYS_LEN);
}

void test_srvkeys(void) {
  test_srvkeys_ticket_accessor();
  test_srvkeys_random_and_distinct();
  test_srvkeys_stable();
  test_srvkeys_token_key_settable();
  test_srvkeys_token_key_known_answer();
}
