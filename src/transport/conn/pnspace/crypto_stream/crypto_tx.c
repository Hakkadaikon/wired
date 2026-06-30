#include "transport/conn/pnspace/crypto_stream/crypto_tx.h"

#include "transport/packet/frame/frame/frame.h"

static usz crypto_tx_min_usz(usz a, usz b) { return a < b ? a : b; }

/* Emit one CRYPTO frame covering chunk bytes from *pos; advance *pos and
 * *written. Returns 1 on success, 0 if it does not fit. */
static int emit_one(
    const u8 *tls_bytes,
    u64       base_offset,
    usz       chunk,
    u8       *out,
    usz       cap,
    usz      *pos,
    usz      *written) {
  quic_crypto_frame f = {base_offset + *pos, chunk, tls_bytes + *pos};
  usz n = quic_frame_put_crypto(out + *written, cap - *written, &f);
  if (n == 0) return 0;
  *written += n;
  *pos += chunk;
  return 1;
}

/* RFC 9000 19.6 */
int quic_crypto_stream_emit(
    const u8 *tls_bytes,
    usz       len,
    u64       base_offset,
    usz       max_frame,
    u8       *out,
    usz       cap,
    usz      *out_len) {
  usz pos = 0, written = 0;
  int ok = max_frame != 0;
  while (ok && pos < len) {
    usz chunk = crypto_tx_min_usz(len - pos, max_frame);
    ok = emit_one(tls_bytes, base_offset, chunk, out, cap, &pos, &written);
  }
  *out_len = written;
  return ok;
}
