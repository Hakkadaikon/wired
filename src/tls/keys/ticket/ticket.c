#include "tls/keys/ticket/ticket.h"

#include "common/bytes/util/be.h"
#include "common/platform/rng/rng.h"
#include "crypto/symmetric/aead/chacha/aead.h"

/* Serialize ticket into the fixed plaintext layout: secret ||
 * issued_at(be64) || lifetime_secs(be32) || age_add(be32). */
static void ticket_encode(const ticket* t, u8 out[TICKET_PLAIN_LEN]) {
  usz i;
  for (i = 0; i < TICKET_SECRET_LEN; i++) out[i] = t->secret[i];
  u8* ts = out + TICKET_SECRET_LEN;
  be_put_be64(ts, t->issued_at);
  be_put_be32(ts + 8, t->lifetime_secs);
  be_put_be32(ts + 12, t->age_add);
}

static void ticket_decode(const u8 in[TICKET_PLAIN_LEN], ticket* t) {
  usz i;
  for (i = 0; i < TICKET_SECRET_LEN; i++) t->secret[i] = in[i];
  const u8* ts     = in + TICKET_SECRET_LEN;
  t->issued_at     = be_get_be64(ts);
  t->lifetime_secs = be_get_be32(ts + 8);
  t->age_add       = be_get_be32(ts + 12);
}

void ticket_seal(const ticket* t, const u8 key[TICKET_KEY_LEN], u8* out) {
  u8 plain[TICKET_PLAIN_LEN];
  ticket_encode(t, plain);

  u8* nonce = out;
  rng_bytes(nonce, TICKET_NONCE_LEN);

  chapoly_ctx c = {key, nonce, {0, 0}};
  chapoly_seal(
      &c, wired_span_of(plain, TICKET_PLAIN_LEN), out + TICKET_NONCE_LEN);
}

int ticket_open(wired_span in, const u8 key[TICKET_KEY_LEN], ticket* out) {
  if (in.n != TICKET_SEALED_LEN) return 0;

  const u8*   nonce    = in.p;
  const u8*   body     = in.p + TICKET_NONCE_LEN;
  usz         body_len = TICKET_PLAIN_LEN + TICKET_TAG_LEN;
  chapoly_ctx c        = {key, nonce, {0, 0}};

  u8 plain[TICKET_PLAIN_LEN];
  if (!chapoly_open(&c, wired_span_of(body, body_len), plain)) return 0;

  ticket_decode(plain, out);
  return 1;
}
