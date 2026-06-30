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
static int hrr_versions(u8 *buf, usz cap, usz *off) {
  u8 ext[6];
  quic_put_be16(ext, QUIC_EXT_SUPPORTED_VERSIONS);
  quic_put_be16(ext + 2, 2);
  quic_put_be16(ext + 4, QUIC_TLS13_VERSION);
  return quic_tls_ext_append(buf, cap, off, ext, 6);
}

/* RFC 8446 4.1.4 key_share carries the selected_group only (no key). */
static int hrr_key_share(u8 *buf, usz cap, usz *off, u16 group) {
  u8 ext[6];
  quic_put_be16(ext, QUIC_EXT_KEY_SHARE);
  quic_put_be16(ext + 2, 2);
  quic_put_be16(ext + 4, group);
  return quic_tls_ext_append(buf, cap, off, ext, 6);
}

/* RFC 8446 4.2.2 cookie: ext_data is opaque cookie<1..2^16-1>. */
/* RFC 8446 4.2.2 cookie header: type(2) ext_len(2) cookie_len(2). */
static int hrr_cookie_hdr(u8 *buf, usz cap, usz *off, usz cl) {
  u8 hdr[6];
  quic_put_be16(hdr, QUIC_EXT_COOKIE);
  quic_put_be16(hdr + 2, (u16)(cl + 2));
  quic_put_be16(hdr + 4, (u16)cl);
  return quic_put_bytes(buf, cap, off, hdr, 6);
}

static int hrr_cookie_body(u8 *buf, usz cap, usz *off, const u8 *ck, usz cl) {
  return hrr_cookie_hdr(buf, cap, off, cl) &&
         quic_put_bytes(buf, cap, off, ck, cl);
}

/* RFC 8446 4.2.2 cookie: ext_data is opaque cookie<1..2^16-1>. */
static int hrr_cookie(u8 *buf, usz cap, usz *off, const u8 *ck, usz cl) {
  if (cl == 0) return 1;
  if (cl > 0xFFFF) return 0;
  return hrr_cookie_body(buf, cap, off, ck, cl);
}

/* Append all extensions; returns body end offset, or 0 on overflow. */
static usz hrr_exts(
    u8 *buf, usz cap, usz off, u16 group, const u8 *ck, usz cl) {
  int ok = hrr_versions(buf, cap, &off);
  ok &= hrr_key_share(buf, cap, &off, group);
  ok &= hrr_cookie(buf, cap, &off, ck, cl);
  return ok ? off : 0;
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

int quic_hrr_build(
    u16       selected_group,
    const u8 *cookie,
    usz       cookie_len,
    u8       *out,
    usz       cap,
    usz      *out_len) {
  usz off = quic_hs_begin(out, cap, QUIC_HS_SERVER_HELLO);
  usz block_start, end;
  if (!hrr_head_fits(off, cap)) return 0;
  off         = hrr_prefix(out, off);
  block_start = off;
  end         = hrr_finish(
      out, hrr_exts(out, cap, off + 2, selected_group, cookie, cookie_len),
      block_start);
  if (end == 0) return 0;
  *out_len = end;
  return 1;
}
