#include "tls/handshake/core/hrr/hrr_build.h"

#include "common/bytes/util/be.h"
#include "common/bytes/util/bytes.h"
#include "tls/handshake/core/tls/ext_block.h"
#include "tls/handshake/core/tls/ext_versions.h"
#include "tls/handshake/core/tls/handshake.h"

/* RFC 8446 4.1.3: SHA-256("HelloRetryRequest"). */
const u8 quic_hrr_random[32] = {0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11,
                                0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
                                0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e,
                                0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c};

#define QUIC_EXT_COOKIE 44

/* RFC 8446 4.1.3 prefix with empty session_id, suite AES_128_GCM_SHA256, and
 * the HRR random sentinel. Returns the offset past it. */
static usz hrr_prefix(u8 *out, usz off) {
  quic_put_be16(out + off, 0x0303);
  for (usz i = 0; i < 32; i++) out[off + 2 + i] = quic_hrr_random[i];
  out[off + 34] = 0; /* empty session_id */
  quic_put_be16(out + off + 35, QUIC_TLS_AES128_GCM_SHA256);
  out[off + 37] = 0; /* compression */
  return off + 38;
}

/* RFC 8446 4.2.1 selected_version 0x0304. */
static int hrr_versions(quic_obuf *out) {
  u8 ext[6];
  quic_put_be16(ext, QUIC_EXT_SUPPORTED_VERSIONS);
  quic_put_be16(ext + 2, 2);
  quic_put_be16(ext + 4, QUIC_TLS13_VERSION);
  return quic_tls_ext_append(out, quic_span_of(ext, 6));
}

/* RFC 8446 4.1.4 key_share carries the selected_group only (no key). */
static int hrr_key_share(quic_obuf *out, u16 group) {
  u8 ext[6];
  quic_put_be16(ext, QUIC_EXT_KEY_SHARE);
  quic_put_be16(ext + 2, 2);
  quic_put_be16(ext + 4, group);
  return quic_tls_ext_append(out, quic_span_of(ext, 6));
}

/* RFC 8446 4.2.2 cookie header: type(2) ext_len(2) cookie_len(2). */
static int hrr_cookie_hdr(quic_obuf *out, usz cl) {
  u8 hdr[6];
  quic_put_be16(hdr, QUIC_EXT_COOKIE);
  quic_put_be16(hdr + 2, (u16)(cl + 2));
  quic_put_be16(hdr + 4, (u16)cl);
  return quic_put_bytes(out->p, out->cap, &out->len, hdr, 6);
}

static int hrr_cookie_body(quic_obuf *out, quic_span ck) {
  return hrr_cookie_hdr(out, ck.n) &&
         quic_put_bytes(out->p, out->cap, &out->len, ck.p, ck.n);
}

/* RFC 8446 4.2.2 cookie: ext_data is opaque cookie<1..2^16-1>. */
static int hrr_cookie(quic_obuf *out, quic_span ck) {
  if (ck.n == 0) return 1;
  if (ck.n > 0xFFFF) return 0;
  return hrr_cookie_body(out, ck);
}

/* Append all extensions; returns body end offset, or 0 on overflow. */
static usz hrr_exts(quic_obuf *out, u16 group, quic_span ck) {
  int ok = hrr_versions(out);
  ok &= hrr_key_share(out, group);
  ok &= hrr_cookie(out, ck);
  return ok ? out->len : 0;
}

/* Finish the extensions block and patch the handshake length. */
static usz hrr_finish(u8 *buf, usz off, usz block_start) {
  usz end;
  if (off == 0) return 0;
  end = quic_tls_ext_block_finish(buf, off, block_start);
  if (end != 0) quic_hs_finish(buf, end);
  return end;
}

/* Header(4) + prefix(38) + ext block length(2) must fit before extensions. */
static int hrr_head_fits(usz off, usz cap) {
  return off != 0 && off + 40 <= cap;
}

int quic_hrr_build(u16 selected_group, quic_span cookie, quic_obuf *out) {
  usz       off = quic_hs_begin(out->p, out->cap, QUIC_HS_SERVER_HELLO);
  usz       block_start, end;
  quic_obuf w;
  if (!hrr_head_fits(off, out->cap)) return 0;
  off         = hrr_prefix(out->p, off);
  block_start = off;
  w           = quic_obuf_of(out->p, out->cap);
  w.len       = off + 2;
  end         = hrr_finish(out->p, hrr_exts(&w, selected_group, cookie), block_start);
  if (end == 0) return 0;
  out->len = end;
  return 1;
}
