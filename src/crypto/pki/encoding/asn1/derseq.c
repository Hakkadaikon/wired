#include "crypto/pki/encoding/asn1/derseq.h"

#include "crypto/pki/encoding/asn1/der.h"

void quic_derseq_init(quic_derseq *c, quic_span seq) {
  c->p   = seq.p;
  c->off = 0;
  c->len = seq.n;
}

/* X.690 8.9. Next element at the cursor, advancing past it. */
int quic_derseq_next(quic_derseq *c, u8 *tag, quic_span *val) {
  quic_der_tlv t;
  if (c->off >= c->len) return 0;
  if (!quic_der_read(quic_span_of(c->p + c->off, c->len - c->off), &t))
    return 0;
  c->off += t.used;
  *tag = t.tag;
  *val = t.val;
  return 1;
}

int quic_derseq_next_tagged(quic_derseq *c, u8 want, quic_span *val) {
  u8 tag;
  if (!quic_derseq_next(c, &tag, val)) return 0;
  return tag == want;
}

int quic_derseq_skip(quic_derseq *c, usz n) {
  u8        tag;
  quic_span val;
  for (usz i = 0; i < n; i++)
    if (!quic_derseq_next(c, &tag, &val)) return 0;
  return 1;
}
