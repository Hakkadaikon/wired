#include "tls/handshake/roles/sflight/certmsg.h"

#include "common/bytes/util/be.h"
#include "common/bytes/util/bytes.h"
#include "tls/handshake/core/tls/handshake.h"

/* RFC 8446 4.4.2 CertificateEntry: cert_data<3> + extensions<2>=empty. */
#define QUIC_HS_CERTIFICATE 11

/* Write a 24-bit big-endian length at p. */
static void put_be24(u8 *p, u32 v) {
  p[0] = (u8)(v >> 16);
  p[1] = (u8)(v >> 8);
  p[2] = (u8)v;
}

/* Header(4) + ctx_len(1) + list_len(3) + entry_len(3) + cert + ext_len(2). */
static int cert_fits(usz cert_len, usz cap) {
  return cert_len <= 0xFFFFFF && 4 + 1 + 3 + 3 + cert_len + 2 <= cap;
}

/* One CertificateEntry into out at out->len; advances out->len past it. */
static void put_entry(quic_obuf *out, quic_span cert) {
  put_be24(out->p + out->len, (u32)cert.n);
  out->len += 3;
  quic_put_bytes(out->p, out->cap, &out->len, cert.p, cert.n); /* room checked */
  quic_put_be16(out->p + out->len, 0); /* empty extensions */
  out->len += 2;
}

int quic_sflight_certificate(quic_span cert_der, quic_obuf *out) {
  usz off;
  if (!cert_fits(cert_der.n, out->cap)) return 0;
  off         = quic_hs_begin(out->p, out->cap, QUIC_HS_CERTIFICATE);
  out->p[off] = 0;                                  /* request_context length 0 */
  put_be24(out->p + off + 1, (u32)(cert_der.n + 5)); /* certificate_list length */
  out->len    = off + 4;
  put_entry(out, cert_der);
  quic_hs_finish(out->p, out->len);
  return 1;
}
