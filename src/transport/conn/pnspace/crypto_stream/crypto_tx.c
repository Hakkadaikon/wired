#include "transport/conn/pnspace/crypto_stream/crypto_tx.h"

#include "transport/packet/frame/frame/frame.h"

static usz crypto_tx_min_usz(usz a, usz b) { return a < b ? a : b; }

/* The next chunk to emit: its base offset and size. */
typedef struct {
  u64 base_offset;
  usz chunk;
} emit_chunk;

/* Progress through tls_bytes: bytes consumed so far (also the frame's payload
 * offset within tls_bytes) and the output cursor. */
typedef struct {
  usz       pos;
  quic_obuf *out;
} emit_progress;

/* Emit one CRYPTO frame covering chunk bytes from p->pos; advance p->pos and
 * p->out->len. Returns 1 on success, 0 if it does not fit. */
static int emit_one(quic_span tls_bytes, const emit_chunk *c, emit_progress *p) {
  quic_crypto_frame f = {
      c->base_offset + p->pos, c->chunk, tls_bytes.p + p->pos};
  usz n = quic_frame_put_crypto(
      p->out->p + p->out->len, p->out->cap - p->out->len, &f);
  if (n == 0) return 0;
  p->out->len += n;
  p->pos += c->chunk;
  return 1;
}

/* RFC 9000 19.6 */
int quic_crypto_stream_emit(
    quic_span tls_bytes, const quic_crypto_stream_emit_in *in, quic_obuf *out) {
  emit_progress p  = {0, out};
  out->len         = 0;
  int ok           = in->max_frame != 0;
  while (ok && p.pos < tls_bytes.n) {
    emit_chunk c = {
        in->base_offset, crypto_tx_min_usz(tls_bytes.n - p.pos, in->max_frame)};
    ok = emit_one(tls_bytes, &c, &p);
  }
  return ok;
}
