#include "tls/keys/ticket/ticket.h"

#include "common/bytes/util/be.h"
#include "common/platform/rng/rng.h"
#include "crypto/symmetric/aead/chacha/aead.h"

/* Serialize quic_ticket into the fixed plaintext layout: secret ||
 * issued_at(be64) || lifetime_secs(be32). */
static void ticket_encode(const quic_ticket* t, u8 out[QUIC_TICKET_PLAIN_LEN]) {
  usz i;
  for (i = 0; i < QUIC_TICKET_SECRET_LEN; i++) out[i] = t->secret[i];
  u8* ts = out + QUIC_TICKET_SECRET_LEN;
  quic_put_be64(ts, t->issued_at);
  quic_put_be32(ts + 8, t->lifetime_secs);
}

static void ticket_decode(const u8 in[QUIC_TICKET_PLAIN_LEN], quic_ticket* t) {
  usz i;
  for (i = 0; i < QUIC_TICKET_SECRET_LEN; i++) t->secret[i] = in[i];
  const u8* ts     = in + QUIC_TICKET_SECRET_LEN;
  t->issued_at     = quic_get_be64(ts);
  t->lifetime_secs = quic_get_be32(ts + 8);
}

void quic_ticket_seal(
    const quic_ticket* t, const u8 key[QUIC_TICKET_KEY_LEN], u8* out) {
  u8 plain[QUIC_TICKET_PLAIN_LEN];
  ticket_encode(t, plain);

  u8* nonce = out;
  quic_rng_bytes(nonce, QUIC_TICKET_NONCE_LEN);

  quic_chapoly_ctx c = {key, nonce, {0, 0}};
  quic_chapoly_seal(
      &c, quic_span_of(plain, QUIC_TICKET_PLAIN_LEN),
      out + QUIC_TICKET_NONCE_LEN);
}

int quic_ticket_open(
    quic_span in, const u8 key[QUIC_TICKET_KEY_LEN], quic_ticket* out) {
  if (in.n != QUIC_TICKET_SEALED_LEN) return 0;

  const u8*        nonce    = in.p;
  const u8*        body     = in.p + QUIC_TICKET_NONCE_LEN;
  usz              body_len = QUIC_TICKET_PLAIN_LEN + QUIC_TICKET_TAG_LEN;
  quic_chapoly_ctx c        = {key, nonce, {0, 0}};

  u8 plain[QUIC_TICKET_PLAIN_LEN];
  if (!quic_chapoly_open(&c, quic_span_of(body, body_len), plain)) return 0;

  ticket_decode(plain, out);
  return 1;
}
