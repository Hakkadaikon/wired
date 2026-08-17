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
    keysched     sched;
    keyset       keys;
    srvfin_state st;
    keysched_init(&sched);
    keyset_init(&keys);
    srvfin_state_init(&st, &sched, &keys);
    CHECK(srvfin_complete(&st, tr, sizeof tr) == 0);
    const initial_keys* k;
    CHECK(keyset_for_level(&keys, LEVEL_ONERTT, &k) == 0);
    CHECK(st.confirmed == 0);
  }

  /* happy path: advance to handshake, then complete installs 1-RTT */
  {
    keysched     sched;
    keyset       keys;
    srvfin_state st;
    keysched_init(&sched);
    keyset_init(&keys);
    srvfin_state_init(&st, &sched, &keys);
    CHECK(
        keysched_advance_handshake(
            &sched, wired_span_of(ecdhe, sizeof ecdhe),
            wired_span_of(tr, sizeof tr)) == 1);
    CHECK(srvfin_complete(&st, tr, sizeof tr) == 1);

    const initial_keys* k;
    CHECK(keyset_for_level(&keys, LEVEL_ONERTT, &k) == 1);
    CHECK(st.confirmed == 1);

    /* installed keys are the server application keys from the schedule */
    const initial_keys* sap;
    CHECK(keysched_get(&sched, KS_SERVER_AP, &sap) == 1);
    for (usz i = 0; i < INITIAL_KEY; i++) CHECK(k->key[i] == sap->key[i]);
  }
}
