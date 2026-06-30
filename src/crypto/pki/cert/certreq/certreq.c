#include "crypto/pki/cert/certreq/certreq.h"

#include "common/bytes/util/be.h"
#include "tls/handshake/core/tls/handshake.h"

#define QUIC_HS_CERTIFICATE_REQUEST 0x0d
#define QUIC_EXT_SIGNATURE_ALGORITHMS 0x000d

/* RFC 8446 4.3.2: write the signature_algorithms extension (type, ext_data
 * length, scheme list length, schemes) at out. Returns bytes written. */
static usz put_sig_algs(u8 *out, const u8 *sa, usz sa_len) {
  quic_put_be16(out, QUIC_EXT_SIGNATURE_ALGORITHMS);
  quic_put_be16(out + 2, (u16)(sa_len + 2));
  quic_put_be16(out + 4, (u16)sa_len);
  for (usz i = 0; i < sa_len; i++) out[6 + i] = sa[i];
  return 6 + sa_len;
}

int quic_certreq_build(
    const u8 *sig_algs, usz sa_len, u8 *out, usz cap, usz *out_len) {
  usz off = quic_hs_begin(out, cap, QUIC_HS_CERTIFICATE_REQUEST);
  usz ext = sa_len + 6;
  if (off == 0 || off + 3 + ext > cap) return 0;
  out[off] = 0;                           /* empty context */
  quic_put_be16(out + off + 1, (u16)ext); /* extensions length */
  put_sig_algs(out + off + 3, sig_algs, sa_len);
  *out_len = off + 3 + ext;
  quic_hs_finish(out, *out_len);
  return 1;
}

/* RFC 8446 4.3.2: read the context and extensions block of the body b (n
 * bytes). Sets ext/ext_len to the extensions block. Returns 1 if framed. */
static int split_body(
    const u8  *b,
    usz        n,
    const u8 **ctx,
    u8        *ctx_len,
    const u8 **ext,
    usz       *ext_len) {
  usz e;
  if (n < 1 || 1 + (usz)b[0] + 2 > n) return 0;
  *ctx     = b + 1;
  *ctx_len = b[0];
  e        = 1 + b[0];
  *ext_len = (usz)b[e] << 8 | b[e + 1];
  *ext     = b + e + 2;
  return e + 2 + *ext_len <= n;
}

/* The extension at offset q is signature_algorithms and its 2-byte list length
 * matches dlen; if so expose the scheme list via sa/sa_len. */
static int sig_algs_here(
    const u8 *ext, usz n, usz q, usz dlen, const u8 **sa, usz *sa_len) {
  usz type = (usz)ext[q] << 8 | ext[q + 1];
  if (type != QUIC_EXT_SIGNATURE_ALGORITHMS || q + 4 + dlen > n) return 0;
  *sa_len = (usz)ext[q + 4] << 8 | ext[q + 5];
  *sa     = ext + q + 6;
  return *sa_len + 2 == dlen;
}

/* Scan an extensions block (n bytes) for signature_algorithms, returning its
 * scheme list via sa/sa_len. RFC 8446 4.3.2. Returns 1 if present. */
static int find_sig_algs(const u8 *ext, usz n, const u8 **sa, usz *sa_len) {
  usz q = 0;
  while (q + 4 <= n) {
    usz dlen = (usz)ext[q + 2] << 8 | ext[q + 3];
    if (sig_algs_here(ext, n, q, dlen, sa, sa_len)) return 1;
    q += 4 + dlen;
  }
  return 0;
}

/* Split the validated body and find signature_algorithms. RFC 8446 4.3.2. */
static int certreq_parse_body(
    const u8  *b,
    usz        n,
    const u8 **ctx,
    u8        *ctx_len,
    const u8 **sa,
    usz       *sa_len) {
  const u8 *ext;
  usz       ext_len;
  if (!split_body(b, n, ctx, ctx_len, &ext, &ext_len)) return 0;
  return find_sig_algs(ext, ext_len, sa, sa_len);
}

int quic_certreq_parse(
    const u8  *msg,
    usz        len,
    const u8 **ctx,
    u8        *ctx_len,
    const u8 **sa,
    usz       *sa_len) {
  u8  type;
  usz body_len;
  usz off = quic_hs_parse(msg, len, &type, &body_len);
  if (off == 0 || type != QUIC_HS_CERTIFICATE_REQUEST) return 0;
  return certreq_parse_body(msg + off, body_len, ctx, ctx_len, sa, sa_len);
}
