#include "test.h"
#include "tls/handshake/roles/srvfin/complete.h"

/* After the client Finished verifies, completing the handshake advances the
 * key schedule to Master, installs the 1-RTT key set, and confirms. Calling
 * complete before the schedule reached the handshake stage is an order
 * violation: nothing is installed and it is not confirmed. */
void test_srvfin_complete(void) {
  u8 ecdhe[32], tr[16];
  for (usz i = 0; i < 32; i++) ecdhe[i] = (u8)(i + 1);
  for (usz i = 0; i < 16; i++) tr[i] = (u8)(0x40 + i);

  /* order violation: schedule still at init stage */
  {
    quic_keysched     sched;
    quic_keyset       keys;
    quic_srvfin_state st;
    quic_keysched_init(&sched);
    quic_keyset_init(&keys);
    quic_srvfin_state_init(&st, &sched, &keys);
    CHECK(quic_srvfin_complete(&st, tr, sizeof tr) == 0);
    const quic_initial_keys *k;
    CHECK(quic_keyset_for_level(&keys, QUIC_LEVEL_ONERTT, &k) == 0);
    CHECK(st.confirmed == 0);
  }

  /* happy path: advance to handshake, then complete installs 1-RTT */
  {
    quic_keysched     sched;
    quic_keyset       keys;
    quic_srvfin_state st;
    quic_keysched_init(&sched);
    quic_keyset_init(&keys);
    quic_srvfin_state_init(&st, &sched, &keys);
    CHECK(
        quic_keysched_advance_handshake(
            &sched, ecdhe, sizeof ecdhe, tr, sizeof tr) == 1);
    CHECK(quic_srvfin_complete(&st, tr, sizeof tr) == 1);

    const quic_initial_keys *k;
    CHECK(quic_keyset_for_level(&keys, QUIC_LEVEL_ONERTT, &k) == 1);
    CHECK(st.confirmed == 1);

    /* installed keys are the server application keys from the schedule */
    const quic_initial_keys *sap;
    CHECK(quic_keysched_get(&sched, QUIC_KS_SERVER_AP, &sap) == 1);
    for (usz i = 0; i < QUIC_INITIAL_KEY; i++) CHECK(k->key[i] == sap->key[i]);
  }
}
