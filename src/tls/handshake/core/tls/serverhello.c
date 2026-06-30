#include "tls/handshake/core/tls/serverhello.h"

#include "tls/handshake/core/tls/ext_keyshare.h"
#include "tls/handshake/core/tls/ext_versions.h"
#include "tls/handshake/core/tls/handshake.h"

/* Skip the ServerHello prefix (RFC 8446 4.1.3): legacy_version(2) random(32)
 * session_id(1+len) cipher_suite(2) compression(1). Sets *cipher and returns
 * the offset of the extensions length field, or 0 if it overruns. */
static usz sh_prefix(const u8 *b, usz n, u16 *cipher, usz *exts) {
  usz p = 34; /* version + random */
  if (n < 35) return 0;
  p += 1 + b[34]; /* session_id */
  if (p + 3 > n) return 0;
  *cipher = (u16)b[p] << 8 | b[p + 1];
  *exts   = p + 3; /* past cipher_suite + compression */
  return *exts;
}

/* Copy the selected version from a ServerHello supported_versions ext_data. */
static void take_version(const u8 *d, usz dlen, u16 *version) {
  if (dlen == 2) *version = (u16)d[0] << 8 | d[1];
}

/* Dispatch one extension (type t, data d, dlen) into the outputs. */
static void sh_ext(
    unsigned t, const u8 *d, usz dlen, u8 pub[32], u16 *version, int *have_ks) {
  if (t == QUIC_EXT_KEY_SHARE)
    *have_ks = quic_tls_ext_key_share_parse(d, dlen, pub);
  else if (t == QUIC_EXT_SUPPORTED_VERSIONS)
    take_version(d, dlen, version);
}

/* Walk the extensions block [q,end) reading version and key_share. */
static int sh_walk(const u8 *b, usz q, usz end, u8 pub[32], u16 *version) {
  int have_ks = 0;
  while (q + 4 <= end) {
    unsigned t    = (unsigned)b[q] << 8 | b[q + 1];
    usz      dlen = (usz)b[q + 2] << 8 | b[q + 3];
    if (q + 4 + dlen > end) return 0;
    sh_ext(t, b + q + 4, dlen, pub, version, &have_ks);
    q += 4 + dlen;
  }
  return have_ks;
}

/* The extensions length at exts is consistent with body length n; sets *end. */
static int sh_block(const u8 *b, usz n, usz exts, usz *q, usz *end) {
  usz blen;
  if (exts + 2 > n) return 0;
  blen = (usz)b[exts] << 8 | b[exts + 1];
  *q   = exts + 2;
  *end = *q + blen;
  return *end <= n;
}

/* The message is a well-framed ServerHello; sets *body_len. */
static int is_server_hello(const u8 *buf, usz n, usz *body_len) {
  u8 type;
  return quic_hs_parse(buf, n, &type, body_len) == 4 &&
         type == QUIC_HS_SERVER_HELLO;
}

/* Locate the extensions block of the ServerHello body b (body_len). */
static int sh_locate(const u8 *b, usz body_len, u16 *cipher, usz *q, usz *end) {
  usz exts;
  return sh_prefix(b, body_len, cipher, &exts) &&
         sh_block(b, body_len, exts, q, end);
}

int quic_tls_parse_server_hello(
    const u8 *buf, usz n, u8 server_pub[32], u16 *cipher, u16 *version) {
  usz body_len, q, end;
  if (!is_server_hello(buf, n, &body_len)) return 0;
  if (!sh_locate(buf + 4, body_len, cipher, &q, &end)) return 0;
  return sh_walk(buf + 4, q, end, server_pub, version);
}
