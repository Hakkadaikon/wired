#include "crypto/pki/cert/certreq/certreq.h"

#include "common/bytes/util/be.h"
#include "tls/handshake/core/tls/handshake.h"

#define QUIC_HS_CERTIFICATE_REQUEST 0x0d
#define QUIC_EXT_SIGNATURE_ALGORITHMS 0x000d

/* RFC 8446 4.3.2: write the signature_algorithms extension (type, ext_data
 * length, scheme list length, schemes) at out. Returns bytes written. */
static usz put_sig_algs(u8 *out, quic_span sa) {
  quic_put_be16(out, QUIC_EXT_SIGNATURE_ALGORITHMS);
  quic_put_be16(out + 2, (u16)(sa.n + 2));
  quic_put_be16(out + 4, (u16)sa.n);
  for (usz i = 0; i < sa.n; i++) out[6 + i] = sa.p[i];
  return 6 + sa.n;
}

int quic_certreq_build(quic_span sig_algs, quic_obuf *out) {
  usz off = quic_hs_begin(out->p, out->cap, QUIC_HS_CERTIFICATE_REQUEST);
  usz ext = sig_algs.n + 6;
  if (off == 0 || off + 3 + ext > out->cap) return 0;
  out->p[off] = 0;                           /* empty context */
  quic_put_be16(out->p + off + 1, (u16)ext); /* extensions length */
  put_sig_algs(out->p + off + 3, sig_algs);
  out->len = off + 3 + ext;
  quic_hs_finish(out->p, out->len);
  return 1;
}

/* RFC 8446 4.3.2: read the context and extensions block of the body b.
 * Sets *ctx and *ext. Returns 1 if framed. */
static int split_body(quic_span b, quic_span *ctx, quic_span *ext) {
  usz e;
  if (b.n < 1 || 1 + (usz)b.p[0] + 2 > b.n) return 0;
  *ctx        = quic_span_of(b.p + 1, b.p[0]);
  e           = 1 + b.p[0];
  usz ext_len = (usz)b.p[e] << 8 | b.p[e + 1];
  *ext        = quic_span_of(b.p + e + 2, ext_len);
  return e + 2 + ext_len <= b.n;
}

/* The 2-byte ext_data length of the extension at offset q. */
static usz ext_dlen(quic_span ext, usz q) {
  return (usz)ext.p[q + 2] << 8 | ext.p[q + 3];
}

/* The extension at offset q is signature_algorithms and its 2-byte list length
 * matches its ext_data length; if so expose the scheme list via *sa. */
static int sig_algs_here(quic_span ext, usz q, quic_span *sa) {
  usz type = (usz)ext.p[q] << 8 | ext.p[q + 1];
  usz dlen = ext_dlen(ext, q);
  if (type != QUIC_EXT_SIGNATURE_ALGORITHMS || q + 4 + dlen > ext.n) return 0;
  usz sa_len = (usz)ext.p[q + 4] << 8 | ext.p[q + 5];
  *sa        = quic_span_of(ext.p + q + 6, sa_len);
  return sa_len + 2 == dlen;
}

/* Scan an extensions block for signature_algorithms, returning its scheme
 * list via *sa. RFC 8446 4.3.2. Returns 1 if present. */
static int find_sig_algs(quic_span ext, quic_span *sa) {
  usz q = 0;
  while (q + 4 <= ext.n) {
    if (sig_algs_here(ext, q, sa)) return 1;
    q += 4 + ext_dlen(ext, q);
  }
  return 0;
}

/* Split the validated body and find signature_algorithms. RFC 8446 4.3.2. */
static int certreq_parse_body(quic_span b, quic_certreq *out) {
  quic_span ext;
  if (!split_body(b, &out->ctx, &ext)) return 0;
  return find_sig_algs(ext, &out->sig_algs);
}

int quic_certreq_parse(quic_span msg, quic_certreq *out) {
  u8  type;
  usz body_len;
  usz off = quic_hs_parse(msg.p, msg.n, &type, &body_len);
  if (off == 0 || type != QUIC_HS_CERTIFICATE_REQUEST) return 0;
  return certreq_parse_body(quic_span_of(msg.p + off, body_len), out);
}
