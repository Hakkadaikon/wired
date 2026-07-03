#include "tls/handshake/core/tls/serverhello.h"

#include "tls/handshake/core/tls/ext_keyshare.h"
#include "tls/handshake/core/tls/ext_versions.h"
#include "tls/handshake/core/tls/handshake.h"

/* Skip the ServerHello prefix (RFC 8446 4.1.3): legacy_version(2) random(32)
 * session_id(1+len) cipher_suite(2) compression(1). Sets *cipher and returns
 * the offset of the extensions length field, or 0 if it overruns. */
static usz sh_prefix(quic_span b, u16 *cipher, usz *exts) {
  usz p = 34; /* version + random */
  if (b.n < 35) return 0;
  p += 1 + b.p[34]; /* session_id */
  if (p + 3 > b.n) return 0;
  *cipher = (u16)b.p[p] << 8 | b.p[p + 1];
  *exts   = p + 3; /* past cipher_suite + compression */
  return *exts;
}

/* Copy the selected version from a ServerHello supported_versions ext_data. */
static void take_version(quic_span d, u16 *version) {
  if (d.n == 2) *version = (u16)d.p[0] << 8 | d.p[1];
}

/* Where a walked extension writes its findings. */
typedef struct {
  u8  *pub;
  u16 *version;
  int  have_ks;
} sh_fields;

/* Dispatch one extension (type t, data d) into fields. */
static void sh_ext(unsigned t, quic_span d, sh_fields *f) {
  if (t == QUIC_EXT_KEY_SHARE)
    f->have_ks = quic_tls_ext_key_share_parse(d.p, d.n, f->pub);
  else if (t == QUIC_EXT_SUPPORTED_VERSIONS)
    take_version(d, f->version);
}

/* Walk the extensions block reading version and key_share. */
static int sh_walk(quic_span block, sh_fields *f) {
  usz q      = 0;
  f->have_ks = 0;
  while (q + 4 <= block.n) {
    unsigned t    = (unsigned)block.p[q] << 8 | block.p[q + 1];
    usz      dlen = (usz)block.p[q + 2] << 8 | block.p[q + 3];
    if (q + 4 + dlen > block.n) return 0;
    sh_ext(t, quic_span_of(block.p + q + 4, dlen), f);
    q += 4 + dlen;
  }
  return f->have_ks;
}

/* The extensions length at exts is consistent with body length n; returns the
 * extensions block as a span. */
static int sh_block(quic_span b, usz exts, quic_span *block) {
  usz blen, q, end;
  if (exts + 2 > b.n) return 0;
  blen = (usz)b.p[exts] << 8 | b.p[exts + 1];
  q    = exts + 2;
  end  = q + blen;
  if (end > b.n) return 0;
  *block = quic_span_of(b.p + q, end - q);
  return 1;
}

/* The message is a well-framed ServerHello; sets *body_len. */
static int is_server_hello(quic_span buf, usz *body_len) {
  u8 type;
  return quic_hs_parse(quic_span_of(buf.p, buf.n), &type, body_len) == 4 &&
         type == QUIC_HS_SERVER_HELLO;
}

/* Locate the extensions block of the ServerHello body b (body_len). */
static int sh_locate(quic_span b, u16 *cipher, quic_span *block) {
  usz exts;
  return sh_prefix(b, cipher, &exts) && sh_block(b, exts, block);
}

int quic_tls_parse_server_hello(
    quic_span buf, u8 server_pub[32], quic_serverhello_out *out) {
  usz       body_len;
  quic_span block;
  sh_fields f = {server_pub, &out->version, 0};
  if (!is_server_hello(buf, &body_len)) return 0;
  if (!sh_locate(quic_span_of(buf.p + 4, body_len), &out->cipher, &block))
    return 0;
  return sh_walk(block, &f);
}
