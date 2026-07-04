#include "crypto/pki/encoding/asn1/der.h"

/* X.690 8.1.3.5. Long-form length octet count: 0x81->1, 0x82->2; 0 if the
 * leading length octet is not a supported long form. */
static usz der_long_n(u8 lead) {
  if (lead == 0x81) return 1;
  if (lead == 0x82) return 2;
  return 0;
}

/* Accumulate nbytes of big-endian length from p+1. Caller guarantees room. */
static usz der_long_val(const u8* p, usz nbytes) {
  usz v = 0;
  for (usz i = 0; i < nbytes; i++) v = (v << 8) | p[1 + i];
  return v;
}

/* True if a long-form length of nb octets is unusable here. */
static int der_long_bad(usz nb, usz lp) { return nb == 0 || lp < 1 + nb; }

/* X.690 8.1.3.5. Long-form length field lf. */
static int der_len_long(quic_span lf, usz* len, usz* hdr) {
  usz nb = der_long_n(lf.p[0]);
  if (der_long_bad(nb, lf.n)) return 0;
  *len = der_long_val(lf.p, nb);
  *hdr = 1 + nb;
  return 1;
}

/* X.690 8.1.3. Parse the length field lf. Sets *len and *hdr (length field
 * octet count). Returns 1 ok, 0 on error. Short + 0x81/0x82 only. */
static int der_len(quic_span lf, usz* len, usz* hdr) {
  if (lf.n < 1) return 0;
  if (lf.p[0] < 0x80) {
    *len = lf.p[0];
    *hdr = 1;
    return 1;
  }
  return der_len_long(lf, len, hdr);
}

/* Read the tag+length header. Returns 1 ok, 0 if too short or malformed. */
static int der_header(quic_span buf, usz* len, usz* head) {
  usz hdr;
  if (buf.n < 2) return 0;
  if (!der_len(quic_span_of(buf.p + 1, buf.n - 1), len, &hdr)) return 0;
  *head = 1 + hdr;
  return 1;
}

int quic_der_read(quic_span buf, quic_der_tlv* out) {
  usz len, head;
  if (!der_header(buf, &len, &head)) return 0;
  if (len > buf.n - head) return 0;
  out->tag  = buf.p[0];
  out->val  = quic_span_of(buf.p + head, len);
  out->used = head + len;
  return 1;
}

int quic_der_seq(quic_span buf, quic_span* val) {
  quic_der_tlv t;
  if (!quic_der_read(buf, &t)) return 0;
  *val = t.val;
  return t.tag == QUIC_DER_SEQUENCE;
}
