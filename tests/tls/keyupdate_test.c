#include "test.h"

/* The Key Phase bit tracks the generation's low bit and toggles on update. */
static void test_keyupdate_phase_tracks(void) {
  quic_keyupdate k;
  quic_keyupdate_init(&k);
  CHECK(quic_keyupdate_phase(&k) == 0);
  quic_keyupdate_initiate(&k);
  CHECK(k.gen == 1 && quic_keyupdate_phase(&k) == 1);
  quic_keyupdate_acked(&k);
  quic_keyupdate_initiate(&k);
  CHECK(k.gen == 2 && quic_keyupdate_phase(&k) == 0);
}

/* A new update is blocked until the previous one is acknowledged, and the
 * generation only ever moves forward. */
static void test_keyupdate_blocked_until_acked(void) {
  quic_keyupdate k;
  quic_keyupdate_init(&k);
  CHECK(quic_keyupdate_initiate(&k) == 1 && k.gen == 1);
  /* second initiate while unacknowledged is refused */
  CHECK(quic_keyupdate_initiate(&k) == 0 && k.gen == 1);
  /* following the peer is also refused while our update is pending */
  CHECK(quic_keyupdate_follow(&k) == 0 && k.gen == 1);
  quic_keyupdate_acked(&k);
  CHECK(quic_keyupdate_initiate(&k) == 1 && k.gen == 2); /* now allowed */
}

/* At most two adjacent generations are retained; the current is always kept. */
static void test_keyupdate_two_adjacent_generations(void) {
  quic_keyupdate k;
  quic_keyupdate_init(&k);
  quic_keyupdate_initiate(&k); /* gen 1, retains {0,1} */
  CHECK(k.lowest == 0 && k.gen == 1);
  quic_keyupdate_acked(&k);
  quic_keyupdate_initiate(&k); /* gen 2, retains {1,2}, drops 0 */
  CHECK(k.lowest == 1 && k.gen == 2);
  CHECK(quic_keyupdate_can_decrypt(&k, 2) == 1); /* current always retained */
  CHECK(quic_keyupdate_can_decrypt(&k, 1) == 1); /* adjacent retained */
  CHECK(quic_keyupdate_can_decrypt(&k, 0) == 0); /* dropped */
}

/* The next generation (one ahead) decrypts on demand; two ahead is refused. */
static void test_keyupdate_decrypt_window(void) {
  quic_keyupdate k;
  quic_keyupdate_init(&k);                       /* gen 0, retains {0} */
  CHECK(quic_keyupdate_can_decrypt(&k, 1) == 1); /* one ahead: on demand */
  CHECK(
      quic_keyupdate_can_decrypt(&k, 2) == 0); /* two ahead: KEY_UPDATE_ERROR */
}

void test_keyupdate(void) {
  test_keyupdate_phase_tracks();
  test_keyupdate_blocked_until_acked();
  test_keyupdate_two_adjacent_generations();
  test_keyupdate_decrypt_window();
}
