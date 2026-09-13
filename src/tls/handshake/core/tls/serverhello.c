#include "tls/handshake/core/tls/serverhello.h"

#include "tls/handshake/core/tls/ext_keyshare.h"
#include "tls/handshake/core/tls/ext_versions.h"
#include "tls/handshake/core/tls/handshake.h"

/* Skip the ServerHello prefix (RFC 8446 4.1.3): legacy_version(2) random(32)
 * session_id(1+len) cipher_suite(2) compression(1). Sets *cipher and returns
 * the offset of the extensions length field, or 0 if it overruns. */
static usz sh_prefix(wired_span b, u16* cipher, usz* exts) {
  usz p = 34; /* version + random */
  if (b.n < 35) return 0;
  p += 1 + b.p[34]; /* session_id */
  if (p + 3 > b.n) return 0;
  *cipher = (u16)b.p[p] << 8 | b.p[p + 1];
  *exts   = p + 3; /* past cipher_suite + compression */
  return *exts;
}

/* Copy the selected version from a ServerHello supported_versions ext_data. */
static void take_version(wired_span d, u16* version) {
  if (d.n == 2) *version = (u16)d.p[0] << 8 | d.p[1];
}

/* Where a walked extension writes its findings. pub_cap is the caller's
 * actual buffer size (32 for the frozen x25519-only entry point, 65 for the
 * either-group one) -- ext_keyshare_parse enforces it before writing a
 * single byte, so a secp256r1 reply can never overrun a 32-byte pub on the
 * x25519-only path (its klen=65 > pub_cap=32 rejects the entry outright). */
typedef struct {
  u8*  pub;
  u16* version;
  u16  group;
  usz  pub_cap;
  int  have_ks;
  int  x25519_only;
} sh_fields;

/* The frozen x25519-only contract: reject anything but x25519/32 bytes. */
static int sh_is_x25519(u16 group, usz pub_len) {
  return group == GROUP_X25519 && pub_len == 32;
}

/* Dispatch one extension (type t, data d) into fields. */
static int sh_ext_keyshare_ok(wired_span d, sh_fields* f) {
  usz pub_len;
  if (!tls_ext_key_share_parse(
          d.p, d.n, &f->group, f->pub, &pub_len, f->pub_cap))
    return 0;
  /* ext_keyshare_parse already checked pub_len against the group */
  return !f->x25519_only || sh_is_x25519(f->group, pub_len);
}

static void sh_ext(unsigned t, wired_span d, sh_fields* f) {
  if (t == EXT_KEY_SHARE)
    f->have_ks = sh_ext_keyshare_ok(d, f);
  else if (t == EXT_SUPPORTED_VERSIONS)
    take_version(d, f->version);
}

/* Walk the extensions block reading version and key_share. */
static int sh_walk(wired_span block, sh_fields* f) {
  usz q      = 0;
  f->have_ks = 0;
  while (q + 4 <= block.n) {
    unsigned t    = (unsigned)block.p[q] << 8 | block.p[q + 1];
    usz      dlen = (usz)block.p[q + 2] << 8 | block.p[q + 3];
    if (q + 4 + dlen > block.n) return 0;
    sh_ext(t, wired_span_of(block.p + q + 4, dlen), f);
    q += 4 + dlen;
  }
  return f->have_ks;
}

/* The extensions length at exts is consistent with body length n; returns the
 * extensions block as a span. */
static int sh_block(wired_span b, usz exts, wired_span* block) {
  usz blen, q, end;
  if (exts + 2 > b.n) return 0;
  blen = (usz)b.p[exts] << 8 | b.p[exts + 1];
  q    = exts + 2;
  end  = q + blen;
  if (end > b.n) return 0;
  *block = wired_span_of(b.p + q, end - q);
  return 1;
}

/* The message is a well-framed ServerHello; sets *body_len. */
static int is_server_hello(wired_span buf, usz* body_len) {
  u8 type;
  return hs_parse(wired_span_of(buf.p, buf.n), &type, body_len) == 4 &&
         type == HS_SERVER_HELLO;
}

/* Locate the extensions block of the ServerHello body b (body_len). */
static int sh_locate(wired_span b, u16* cipher, wired_span* block) {
  usz exts;
  return sh_prefix(b, cipher, &exts) && sh_block(b, exts, block);
}

/* RFC 8446 4.1.3: ServerHello.legacy_version MUST be 0x0303. */
static int sh_legacy_version_ok(wired_span b) {
  return b.p[0] == 0x03 && b.p[1] == 0x03;
}

/* RFC 8446 4.1.3: the last 8 bytes of random equal "DOWNGRD" || 0x01 (a
 * TLS 1.2 server's downgrade sentinel) or "DOWNGRD" || 0x00 (TLS 1.1 and
 * below). b is the body: random spans [2, 34), its tail starts at 26. */
static int sh_downgrade_sentinel(wired_span b) {
  static const u8 downgrd[7] = {0x44, 0x4f, 0x57, 0x4e, 0x47, 0x52, 0x44};
  const u8*       r          = b.p + 26;
  for (usz i = 0; i < 7; i++)
    if (r[i] != downgrd[i]) return 0;
  return r[7] <= 1;
}

/* RFC 8446 4.2.1 / Appendix D.1: the server's selected version MUST be
 * TLS 1.3 (supported_versions present and 0x0304), legacy_version MUST be
 * 0x0303, and the random MUST NOT carry a downgrade sentinel -- anything
 * else is a downgrade a TLS-1.3-only client aborts (protocol_version). */
static int sh_version_ok(wired_span body, u16 version) {
  return version == 0x0304 && sh_legacy_version_ok(body) &&
         !sh_downgrade_sentinel(body);
}

/* Locate the extensions block of body, walk it into *f, then enforce the
 * version/downgrade checks over what was taken. */
static int sh_take(wired_span body, serverhello_out* out, sh_fields* f) {
  wired_span block;
  if (!sh_locate(body, &out->cipher, &block)) return 0;
  return sh_walk(block, f) && sh_version_ok(body, out->version);
}

/* Shared body for both entry points: locate the extensions block and walk
 * it into *f (pub/version/pub_cap/x25519_only already set by the caller). */
static int sh_parse(wired_span buf, serverhello_out* out, sh_fields* f) {
  usz body_len;
  f->version   = &out->version;
  out->version = 0; /* absent supported_versions must not read as 1.3 */
  if (!is_server_hello(buf, &body_len)) return 0;
  return sh_take(wired_span_of(buf.p + 4, body_len), out, f);
}

int tls_parse_server_hello(
    wired_span buf, u8 server_pub[32], serverhello_out* out) {
  sh_fields f = {server_pub, 0, 0, 32, 0, 1};
  return sh_parse(buf, out, &f);
}

int tls_parse_server_hello_group(
    wired_span buf, u8 server_pub[65], u16* group, serverhello_out* out) {
  sh_fields f = {server_pub, 0, 0, 65, 0, 0};
  if (!sh_parse(buf, out, &f)) return 0;
  *group = f.group;
  return 1;
}
