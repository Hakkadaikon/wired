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
 * this one issued. The two keys differ (one seed, two uses). */
static void test_srvkeys_token_key_settable(void) {
  u8 a[SRVKEYS_LEN], b[SRVKEYS_LEN], nt[SRVKEYS_LEN];
  srvkeys_test_seed(a, 0x30);
  srvkeys_test_seed(b, 0x60);
  CHECK(wired_srvkeys_set_token_key(a) == 1);
  CHECK(ct_diffn(srvkeys_retry(), a, SRVKEYS_LEN) == 0);
  CHECK(ct_diffn(srvkeys_newtoken(), a, SRVKEYS_LEN) != 0);
  bytes_memcpy(nt, srvkeys_newtoken(), SRVKEYS_LEN);
  CHECK(wired_srvkeys_set_token_key(b) == 1);
  CHECK(ct_diffn(srvkeys_newtoken(), nt, SRVKEYS_LEN) != 0);
  CHECK(wired_srvkeys_set_token_key(a) == 1);
  CHECK(ct_diffn(srvkeys_newtoken(), nt, SRVKEYS_LEN) == 0);
}

void test_srvkeys(void) {
  test_srvkeys_ticket_accessor();
  test_srvkeys_random_and_distinct();
  test_srvkeys_stable();
  test_srvkeys_token_key_settable();
}
