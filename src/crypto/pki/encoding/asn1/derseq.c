#include "crypto/pki/encoding/asn1/derseq.h"

#include "crypto/pki/encoding/asn1/der.h"

void derseq_init(derseq* c, wired_span seq) {
  c->p   = seq.p;
  c->off = 0;
  c->len = seq.n;
}

/* X.690 8.9. Next element at the cursor, advancing past it. */
int derseq_next(derseq* c, u8* tag, wired_span* val) {
  der_tlv t;
  if (c->off >= c->len) return 0;
  if (!der_read(wired_span_of(c->p + c->off, c->len - c->off), &t)) return 0;
  c->off += t.used;
  *tag = t.tag;
  *val = t.val;
  return 1;
}

int derseq_next_tagged(derseq* c, u8 want, wired_span* val) {
  u8 tag;
  if (!derseq_next(c, &tag, val)) return 0;
  return tag == want;
}

int derseq_skip(derseq* c, usz n) {
  u8         tag;
  wired_span val;
  for (usz i = 0; i < n; i++)
    if (!derseq_next(c, &tag, &val)) return 0;
  return 1;
}
