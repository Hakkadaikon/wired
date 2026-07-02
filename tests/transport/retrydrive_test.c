#include "test.h"

/* RFC 9000 17.2.5.2: accept the first Retry with a valid tag, discard the
 * rest. */
static void test_retrydrive_accept(void) {
  CHECK(quic_retrydrive_accept(0, 1) == 1); /* first + valid tag */
  CHECK(quic_retrydrive_accept(1, 1) == 0); /* second Retry */
  CHECK(quic_retrydrive_accept(0, 0) == 0); /* invalid tag */
  CHECK(quic_retrydrive_accept(1, 0) == 0); /* second + invalid */
}

/* RFC 9000 17.2.5.2 / RFC 9001 5.2: apply stores the token, adopts the SCID as
 * the new DCID, and flags Initial key re-derivation. */
static void test_retrydrive_apply(void) {
  const u8              tok[]  = {0xde, 0xad, 0xbe, 0xef};
  const u8              scid[] = {1, 2, 3, 4, 5, 6, 7, 8};
  quic_retrydrive_state s      = {0};

  CHECK(
      quic_retrydrive_apply(
          quic_span_of(tok, sizeof tok), quic_span_of(scid, sizeof scid), &s) ==
      1);
  CHECK(s.received == 1);
  CHECK(s.key_rederive == 1);
  CHECK(s.token_len == sizeof tok);
  for (usz i = 0; i < sizeof tok; i++) CHECK(s.token[i] == tok[i]);
  CHECK(s.dcid_len == sizeof scid);
  for (usz i = 0; i < sizeof scid; i++) CHECK(s.dcid[i] == scid[i]);
}

/* apply rejects a token larger than the state buffer. */
static void test_retrydrive_apply_overflow(void) {
  u8                    big[257] = {0};
  const u8              scid[]   = {9};
  quic_retrydrive_state s        = {0};

  CHECK(
      quic_retrydrive_apply(
          quic_span_of(big, sizeof big), quic_span_of(scid, sizeof scid), &s) ==
      0);
  CHECK(s.received == 0); /* untouched */
}

/* RFC 9000 17.2.5.1: empty token before a Retry, stored token after. */
static void test_retrydrive_initial_token(void) {
  const u8              tok[]  = {0xaa, 0xbb, 0xcc};
  const u8              scid[] = {1, 2, 3, 4};
  quic_retrydrive_state s      = {0};
  const u8             *t;
  usz                   len;

  quic_retrydrive_initial_token(&s, &t, &len);
  CHECK(len == 0); /* no Retry yet -> empty token */

  quic_retrydrive_apply(
      quic_span_of(tok, sizeof tok), quic_span_of(scid, sizeof scid), &s);
  quic_retrydrive_initial_token(&s, &t, &len);
  CHECK(len == sizeof tok);
  for (usz i = 0; i < sizeof tok; i++) CHECK(t[i] == tok[i]);
}

void test_retrydrive(void) {
  test_retrydrive_accept();
  test_retrydrive_apply();
  test_retrydrive_apply_overflow();
  test_retrydrive_initial_token();
}
