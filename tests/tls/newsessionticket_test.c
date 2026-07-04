#include "test.h"

static void fill_nst_key(u8 key[QUIC_TICKET_KEY_LEN], u8 v) {
  for (usz i = 0; i < QUIC_TICKET_KEY_LEN; i++) key[i] = v;
}

static quic_ticket nst_sample_ticket(void) {
  quic_ticket t;
  for (usz i = 0; i < QUIC_TICKET_SECRET_LEN; i++) t.secret[i] = (u8)(i + 1);
  t.issued_at     = 1720000000ULL;
  t.lifetime_secs = 7200;
  return t;
}

/* The encoded message starts with the NewSessionTicket handshake type and a
 * self-consistent 24-bit length (RFC 8446 4 handshake framing). */
static void test_nst_header(void) {
  u8          key[QUIC_TICKET_KEY_LEN];
  quic_ticket t = nst_sample_ticket();
  u8          out[256];
  usz         n;
  fill_nst_key(key, 0x11);
  n = quic_tls_new_session_ticket_encode(out, sizeof out, &t, key);
  CHECK(n > 4);
  CHECK(out[0] == QUIC_HS_NEW_SESSION_TICKET);
  usz body = ((usz)out[1] << 16) | ((usz)out[2] << 8) | out[3];
  CHECK(4 + body == n);
}

/* Too small a buffer is rejected, not overrun. */
static void test_nst_no_room(void) {
  u8          key[QUIC_TICKET_KEY_LEN];
  quic_ticket t = nst_sample_ticket();
  u8          out[8];
  fill_nst_key(key, 0x22);
  CHECK(quic_tls_new_session_ticket_encode(out, sizeof out, &t, key) == 0);
}

/* Parsing the encoded message back out and opening the sealed ticket with the
 * same key restores the original secret/lifetime (the field this SDK needs
 * for later resumption); a bogus key must reject it. */
static void test_nst_roundtrip(void) {
  u8          key[QUIC_TICKET_KEY_LEN];
  quic_ticket t = nst_sample_ticket();
  u8          out[256];
  usz         n;
  quic_span   sealed;
  quic_ticket opened;
  u8          wrong_key[QUIC_TICKET_KEY_LEN];

  fill_nst_key(key, 0x33);
  n = quic_tls_new_session_ticket_encode(out, sizeof out, &t, key);
  CHECK(n > 0);

  CHECK(quic_tls_new_session_ticket_parse(quic_span_of(out, n), &sealed) == 1);
  CHECK(quic_ticket_open(sealed, key, &opened) == 1);
  CHECK(opened.lifetime_secs == t.lifetime_secs);
  CHECK(opened.issued_at == t.issued_at);
  for (usz i = 0; i < QUIC_TICKET_SECRET_LEN; i++)
    CHECK(opened.secret[i] == t.secret[i]);

  fill_nst_key(wrong_key, 0x44);
  CHECK(quic_ticket_open(sealed, wrong_key, &opened) == 0);
}

/* A truncated message (shorter than its own header claims) is rejected. */
static void test_nst_parse_truncated(void) {
  u8          key[QUIC_TICKET_KEY_LEN];
  quic_ticket t = nst_sample_ticket();
  u8          out[256];
  usz         n;
  quic_span   sealed;
  fill_nst_key(key, 0x55);
  n = quic_tls_new_session_ticket_encode(out, sizeof out, &t, key);
  CHECK(
      quic_tls_new_session_ticket_parse(quic_span_of(out, n - 1), &sealed) ==
      0);
}

void test_newsessionticket(void) {
  test_nst_header();
  test_nst_no_room();
  test_nst_roundtrip();
  test_nst_parse_truncated();
}
