#include "crypto/pki/encoding/asn1/derseq.h"

#include "crypto/pki/encoding/asn1/der.h"

void quic_derseq_init(quic_derseq *c, const u8 *seq_val, usz seq_len) {
  c->p   = seq_val;
  c->off = 0;
  c->len = seq_len;
}

/* X.690 8.9. Next element at the cursor, advancing past it. */
int quic_derseq_next(quic_derseq *c, u8 *tag, const u8 **val, usz *val_len) {
  if (c->off >= c->len) return 0;
  usz consumed;
  if (!quic_der_read(
          c->p + c->off, c->len - c->off, tag, val, val_len, &consumed))
    return 0;
  c->off += consumed;
  return 1;
}
