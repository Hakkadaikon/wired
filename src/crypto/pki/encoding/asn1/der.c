#include "crypto/pki/encoding/asn1/der.h"

/* X.690 8.1.3.5. Long-form length octet count: 0x81->1, 0x82->2; 0 if the
 * leading length octet is not a supported long form. */
static usz der_long_n(u8 lead) {
  if (lead == 0x81) return 1;
  if (lead == 0x82) return 2;
  return 0;
}

/* Accumulate nbytes of big-endian length from p+1. Caller guarantees room. */
static usz der_long_val(const u8 *p, usz nbytes) {
  usz v = 0;
  for (usz i = 0; i < nbytes; i++) v = (v << 8) | p[1 + i];
  return v;
}

/* True if a long-form length of nb octets is unusable here. */
static int der_long_bad(usz nb, usz lp) { return nb == 0 || lp < 1 + nb; }

/* X.690 8.1.3.5. Long-form length at p (lp octets). */
static int der_len_long(const u8 *p, usz lp, usz *len, usz *hdr) {
  usz nb = der_long_n(p[0]);
  if (der_long_bad(nb, lp)) return 0;
  *len = der_long_val(p, nb);
  *hdr = 1 + nb;
  return 1;
}

/* X.690 8.1.3. Parse length at p (lp octets). Sets *len and *hdr (length
 * field octet count). Returns 1 ok, 0 on error. Short + 0x81/0x82 only. */
static int der_len(const u8 *p, usz lp, usz *len, usz *hdr) {
  if (lp < 1) return 0;
  if (p[0] < 0x80) {
    *len = p[0];
    *hdr = 1;
    return 1;
  }
  return der_len_long(p, lp, len, hdr);
}

/* Read the tag+length header. Returns 1 ok, 0 if too short or malformed. */
static int der_header(const u8 *buf, usz n, usz *len, usz *head) {
  usz hdr;
  if (n < 2) return 0;
  if (!der_len(buf + 1, n - 1, len, &hdr)) return 0;
  *head = 1 + hdr;
  return 1;
}

int quic_der_read(
    const u8  *buf,
    usz        n,
    u8        *tag,
    const u8 **val,
    usz       *val_len,
    usz       *consumed) {
  usz len, head;
  if (!der_header(buf, n, &len, &head)) return 0;
  if (len > n - head) return 0;
  *tag      = buf[0];
  *val      = buf + head;
  *val_len  = len;
  *consumed = head + len;
  return 1;
}
