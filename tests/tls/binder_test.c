#include "test.h"

/* RFC 8446 4.2.11.2 PSK binder: compute+verify round-trip and the reject
 * paths (flipped binder byte, tampered transcript, wrong PSK). */

static void binder_fill(u8* p, usz n, u8 base) {
  for (usz i = 0; i < n; i++) p[i] = (u8)(base + i);
}

static void test_binder_verify_ok(void) {
  u8 psk[32];
  binder_fill(psk, 32, 0x40);
  const u8 ch[] = "ClientHello-truncated-up-to-identities";
  u8       binder[32];
  quic_tls_binder_compute(psk, quic_span_of(ch, sizeof(ch)), binder);
  CHECK(quic_tls_binder_verify(psk, quic_span_of(ch, sizeof(ch)), binder));
}

static void test_binder_reject_flipped_binder_byte(void) {
  u8 psk[32];
  binder_fill(psk, 32, 0x40);
  const u8 ch[] = "ClientHello-truncated-up-to-identities";
  u8       binder[32];
  quic_tls_binder_compute(psk, quic_span_of(ch, sizeof(ch)), binder);
  binder[0] ^= 0x01;
  CHECK(!quic_tls_binder_verify(psk, quic_span_of(ch, sizeof(ch)), binder));
}

static void test_binder_reject_tampered_transcript(void) {
  u8 psk[32];
  binder_fill(psk, 32, 0x40);
  const u8 ch[]  = "ClientHello-truncated-up-to-identities";
  const u8 ch2[] = "ClientHello-TAMPERED-up-to-identities!";
  u8       binder[32];
  quic_tls_binder_compute(psk, quic_span_of(ch, sizeof(ch)), binder);
  CHECK(!quic_tls_binder_verify(psk, quic_span_of(ch2, sizeof(ch2)), binder));
}

static void test_binder_reject_wrong_psk(void) {
  u8 psk_a[32], psk_b[32];
  binder_fill(psk_a, 32, 0x40);
  binder_fill(psk_b, 32, 0x41);
  const u8 ch[] = "ClientHello-truncated-up-to-identities";
  u8       binder[32];
  quic_tls_binder_compute(psk_a, quic_span_of(ch, sizeof(ch)), binder);
  CHECK(!quic_tls_binder_verify(psk_b, quic_span_of(ch, sizeof(ch)), binder));
}

static void test_binder_deterministic(void) {
  u8 psk[32];
  binder_fill(psk, 32, 0x40);
  const u8 ch[] = "ClientHello-truncated-up-to-identities";
  u8       b1[32], b2[32];
  quic_tls_binder_compute(psk, quic_span_of(ch, sizeof(ch)), b1);
  quic_tls_binder_compute(psk, quic_span_of(ch, sizeof(ch)), b2);
  for (usz i = 0; i < 32; i++) CHECK(b1[i] == b2[i]);
}

/* Self-consistency sub-vector (RFC 8448 full trace was not retrievable in
 * this environment -- no network access from the sandbox; per this repo's
 * rule against faking a golden match, cross-check binder_key against the
 * same already-vetted HKDF primitives composed independently in the test,
 * rather than pinning an unverified external hex string). quic_hkdf_extract
 * and quic_hkdf_expand_label are themselves pinned against RFC 5869 Appendix
 * A.1 in tests/crypto/hkdf_test.c; this proves quic_tls_binder_key performs
 * exactly early_secret=HKDF-Extract(0,psk),
 * binder_key=Derive-Secret(early_secret,"res binder","") and nothing else,
 * by recomputing it a second, independent way. */
static void test_binder_key_matches_manual_derivation(void) {
  u8 psk[32];
  binder_fill(psk, 32, 0x55);
  u8 zero[32] = {0};
  u8 early[32];
  quic_hkdf_extract(quic_span_of(zero, 32), quic_span_of(psk, 32), early);

  u8 empty_hash[32];
  quic_sha256(zero, 0, empty_hash); /* Transcript-Hash("") */
  quic_hkdf_label l = {"res binder", 10, {empty_hash, 32}};
  u8              want[32];
  CHECK(quic_hkdf_expand_label(early, &l, quic_mspan_of(want, 32)));

  u8 got[32];
  quic_tls_binder_key(psk, got);
  for (usz i = 0; i < 32; i++) CHECK(got[i] == want[i]);
}

void test_binder(void) {
  test_binder_verify_ok();
  test_binder_reject_flipped_binder_byte();
  test_binder_reject_tampered_transcript();
  test_binder_reject_wrong_psk();
  test_binder_deterministic();
  test_binder_key_matches_manual_derivation();
}
