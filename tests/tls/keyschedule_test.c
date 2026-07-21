#include "test.h"

static void fill(u8* p, usz n, u8 base) {
  for (usz i = 0; i < n; i++) p[i] = (u8)(base + i);
}

static int keys_differ(const quic_initial_keys* a, const quic_initial_keys* b) {
  int d = 0;
  for (usz i = 0; i < QUIC_INITIAL_KEY; i++) d |= (a->key[i] != b->key[i]);
  return d;
}

/* Ordered drive: init -> handshake -> master makes each stage's keys
 * retrievable, and only after its stage is reached. */
static void test_keyschedule_order(void) {
  u8 ecdhe[32], tr[] = "ClientHello||ServerHello";
  fill(ecdhe, 32, 1);
  quic_keysched            st;
  const quic_initial_keys* k;

  quic_keysched_init(&st);
  /* nothing derived yet */
  CHECK(quic_keysched_get(&st, QUIC_KS_CLIENT_HS, &k) == 0);
  CHECK(quic_keysched_get(&st, QUIC_KS_CLIENT_AP, &k) == 0);

  CHECK(
      quic_keysched_advance_handshake(
          &st, quic_span_of(ecdhe, 32), quic_span_of(tr, sizeof(tr))) == 1);
  CHECK(quic_keysched_get(&st, QUIC_KS_CLIENT_HS, &k) == 1);
  CHECK(quic_keysched_get(&st, QUIC_KS_SERVER_HS, &k) == 1);
  /* app keys still unavailable before master stage */
  CHECK(quic_keysched_get(&st, QUIC_KS_CLIENT_AP, &k) == 0);

  CHECK(quic_keysched_advance_master(&st, tr, sizeof(tr)) == 1);
  CHECK(quic_keysched_get(&st, QUIC_KS_CLIENT_AP, &k) == 1);
  CHECK(quic_keysched_get(&st, QUIC_KS_SERVER_AP, &k) == 1);
}

/* Skipping the handshake stage (init -> master directly) is rejected. */
static void test_keyschedule_skip_rejected(void) {
  u8                       tr[] = "transcript";
  quic_keysched            st;
  const quic_initial_keys* k;
  quic_keysched_init(&st);
  CHECK(quic_keysched_advance_master(&st, tr, sizeof(tr)) == 0);
  CHECK(quic_keysched_get(&st, QUIC_KS_CLIENT_AP, &k) == 0);
}

/* Advancing handshake twice is rejected (stage no longer init). */
static void test_keyschedule_double_handshake(void) {
  u8 ecdhe[32], tr[] = "tr";
  fill(ecdhe, 32, 5);
  quic_keysched st;
  quic_keysched_init(&st);
  CHECK(
      quic_keysched_advance_handshake(
          &st, quic_span_of(ecdhe, 32), quic_span_of(tr, sizeof(tr))) == 1);
  CHECK(
      quic_keysched_advance_handshake(
          &st, quic_span_of(ecdhe, 32), quic_span_of(tr, sizeof(tr))) == 0);
}

/* A wrong-length ECDHE secret is rejected at the trust boundary. */
static void test_keyschedule_bad_ecdhe(void) {
  u8 ecdhe[32], tr[] = "tr";
  fill(ecdhe, 32, 9);
  quic_keysched st;
  quic_keysched_init(&st);
  CHECK(
      quic_keysched_advance_handshake(
          &st, quic_span_of(ecdhe, 31), quic_span_of(tr, sizeof(tr))) == 0);
  CHECK(st.stage == 0); /* stage unchanged on rejection */
}

/* Driven keys match the existing one-shot derivations and split by direction.
 */
static void test_keyschedule_matches_oneshot(void) {
  u8 ecdhe[32], tr[] = "ClientHello||ServerHello||Finished";
  fill(ecdhe, 32, 3);
  quic_keysched            st;
  const quic_initial_keys *c_hs, *s_hs, *c_ap, *s_ap;
  quic_keysched_init(&st);
  quic_keysched_advance_handshake(
      &st, quic_span_of(ecdhe, 32), quic_span_of(tr, sizeof(tr)));
  quic_keysched_advance_master(&st, tr, sizeof(tr));
  quic_keysched_get(&st, QUIC_KS_CLIENT_HS, &c_hs);
  quic_keysched_get(&st, QUIC_KS_SERVER_HS, &s_hs);
  quic_keysched_get(&st, QUIC_KS_CLIENT_AP, &c_ap);
  quic_keysched_get(&st, QUIC_KS_SERVER_AP, &s_ap);

  u8                hs[32], master[32];
  quic_initial_keys ref;
  quic_tls_handshake_secret(ecdhe, hs);
  quic_tls_handshake_keys(
      &(quic_handshake_keys_in){hs, quic_span_of(tr, sizeof(tr)), 0}, &ref);
  for (usz i = 0; i < QUIC_INITIAL_KEY; i++) CHECK(c_hs->key[i] == ref.key[i]);
  quic_tls_master_secret(hs, master);
  quic_tls_app_keys(
      &(quic_app_keys_in){master, quic_span_of(tr, sizeof(tr)), 1}, &ref);
  for (usz i = 0; i < QUIC_INITIAL_KEY; i++) CHECK(s_ap->key[i] == ref.key[i]);

  /* directions and stages produce distinct keys */
  CHECK(keys_differ(c_hs, s_hs));
  CHECK(keys_differ(c_ap, s_ap));
  CHECK(keys_differ(c_hs, c_ap));
}

/* RFC 8446 7.1 PSK branch: quic_keysched_advance_handshake_psk installs
 * the same Handshake-level keys and Master Secret as an independent
 * quic_tls_handshake_secret_psk + quic_tls_handshake_keys/quic_tls_master_
 * secret computation over the same psk/ecdhe/transcript. */
static void test_keyschedule_psk_matches_oneshot(void) {
  u8 psk[32], ecdhe[32], tr[] = "ClientHello(psk)||ServerHello";
  fill(psk, 32, 7);
  fill(ecdhe, 32, 3);
  quic_keysched            st;
  const quic_initial_keys *c_hs, *s_hs;
  quic_keysched_init(&st);
  CHECK(
      quic_keysched_advance_handshake_psk(
          &st, quic_span_of(psk, 32), quic_span_of(ecdhe, 32),
          quic_span_of(tr, sizeof(tr))) == 1);
  quic_keysched_get(&st, QUIC_KS_CLIENT_HS, &c_hs);
  quic_keysched_get(&st, QUIC_KS_SERVER_HS, &s_hs);

  u8                hs[32], master[32];
  quic_initial_keys ref;
  quic_tls_handshake_secret_psk(psk, ecdhe, hs);
  quic_tls_handshake_keys(
      &(quic_handshake_keys_in){hs, quic_span_of(tr, sizeof(tr)), 0}, &ref);
  for (usz i = 0; i < QUIC_INITIAL_KEY; i++) CHECK(c_hs->key[i] == ref.key[i]);
  quic_tls_handshake_keys(
      &(quic_handshake_keys_in){hs, quic_span_of(tr, sizeof(tr)), 1}, &ref);
  for (usz i = 0; i < QUIC_INITIAL_KEY; i++) CHECK(s_hs->key[i] == ref.key[i]);
  quic_tls_master_secret(hs, master);
  for (usz i = 0; i < 32; i++) CHECK(st.master[i] == master[i]);
}

/* Same psk/ecdhe/transcript, PSK vs plain branch: the derived Handshake keys
 * differ -- the PSK is actually mixed into the Early Secret (RFC 8446 7.1),
 * not silently ignored. */
static void test_keyschedule_psk_differs_from_plain(void) {
  u8 psk[32], ecdhe[32], tr[] = "same-transcript";
  fill(psk, 32, 11);
  fill(ecdhe, 32, 13);
  quic_keysched            st_psk, st_plain;
  const quic_initial_keys *psk_hs, *plain_hs;
  quic_keysched_init(&st_psk);
  quic_keysched_init(&st_plain);
  quic_keysched_advance_handshake_psk(
      &st_psk, quic_span_of(psk, 32), quic_span_of(ecdhe, 32),
      quic_span_of(tr, sizeof(tr)));
  quic_keysched_advance_handshake(
      &st_plain, quic_span_of(ecdhe, 32), quic_span_of(tr, sizeof(tr)));
  quic_keysched_get(&st_psk, QUIC_KS_SERVER_HS, &psk_hs);
  quic_keysched_get(&st_plain, QUIC_KS_SERVER_HS, &plain_hs);
  CHECK(keys_differ(psk_hs, plain_hs));
}

/* A wrong-length ECDHE secret is rejected on the PSK branch too. */
static void test_keyschedule_psk_bad_ecdhe(void) {
  u8 psk[32], ecdhe[32], tr[] = "tr";
  fill(psk, 32, 2);
  fill(ecdhe, 32, 9);
  quic_keysched st;
  quic_keysched_init(&st);
  CHECK(
      quic_keysched_advance_handshake_psk(
          &st, quic_span_of(psk, 32), quic_span_of(ecdhe, 31),
          quic_span_of(tr, sizeof(tr))) == 0);
  CHECK(st.stage == 0);
}

void test_keyschedule(void) {
  test_keyschedule_order();
  test_keyschedule_skip_rejected();
  test_keyschedule_double_handshake();
  test_keyschedule_bad_ecdhe();
  test_keyschedule_matches_oneshot();
  test_keyschedule_psk_matches_oneshot();
  test_keyschedule_psk_differs_from_plain();
  test_keyschedule_psk_bad_ecdhe();
}
