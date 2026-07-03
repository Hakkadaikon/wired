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

/* One CertificateEntry into out at out->len; advances out->len past it. */
static void put_entry(quic_obuf *out, quic_span cert) {
  put_be24(out->p + out->len, (u32)cert.n);
  out->len += 3;
  quic_put_bytes(
      quic_mspan_of(out->p, out->cap), &out->len,
      quic_span_of(cert.p, cert.n));   /* room checked */
  quic_put_be16(out->p + out->len, 0); /* empty extensions */
  out->len += 2;
}

/* Total certificate_list bytes for certs[0..count): each entry is
 * len(3) + cert_data + extensions(2). */
static usz certchain_wire_len(const quic_span *certs, usz count) {
  usz total = 0;
  for (usz i = 0; i < count; i++) total += 3 + certs[i].n + 2;
  return total;
}

/* count is in 1..QUIC_TLS_CERT_CHAIN_MAX. */
static int certchain_count_ok(usz count) {
  return count >= 1 && count <= QUIC_TLS_CERT_CHAIN_MAX;
}

/* Header(4) + ctx_len(1) + list_len(3) + list_len bytes fit in cap. */
static int certchain_fits(usz list_len, usz cap) {
  return list_len <= 0xFFFFFF && 4 + 1 + 3 + list_len <= cap;
}

static int certchain_ok(const quic_sflight_certchain_in *in, usz cap) {
  usz list_len;
  if (!certchain_count_ok(in->count)) return 0;
  list_len = certchain_wire_len(in->certs, in->count);
  return certchain_fits(list_len, cap);
}

int quic_sflight_certificate_chain(
    const quic_sflight_certchain_in *in, quic_obuf *out) {
  usz off, list_len;
  if (!certchain_ok(in, out->cap)) return 0;
  list_len    = certchain_wire_len(in->certs, in->count);
  off         = quic_hs_begin(out->p, out->cap, QUIC_HS_CERTIFICATE);
  out->p[off] = 0; /* request_context length 0 */
  put_be24(out->p + off + 1, (u32)list_len);
  out->len = off + 4;
  for (usz i = 0; i < in->count; i++) put_entry(out, in->certs[i]);
  quic_hs_finish(out->p, out->len);
  return 1;
}

int quic_sflight_certificate(quic_span cert_der, quic_obuf *out) {
  quic_sflight_certchain_in in = {&cert_der, 1};
  return quic_sflight_certificate_chain(&in, out);
}
