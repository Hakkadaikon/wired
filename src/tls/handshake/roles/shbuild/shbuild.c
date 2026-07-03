#include "tls/handshake/roles/shbuild/shbuild.h"

#include "common/bytes/util/be.h"
#include "tls/handshake/core/tls/ext_block.h"
#include "tls/handshake/core/tls/ext_versions.h"
#include "tls/handshake/core/tls/handshake.h"

/* RFC 8446 4.1.3 prefix: legacy_version(2) random(32) session_id(1+sid_len)
 * cipher_suite(2) legacy_compression_method(1). Returns the offset past it. */
static usz shb_prefix(
    u8       *out,
    usz       off,
    const u8  random[32],
    const u8 *sid,
    u8        sid_len,
    u16       cipher) {
  quic_put_be16(out + off, 0x0303);
  for (usz i = 0; i < 32; i++) out[off + 2 + i] = random[i];
  out[off + 34] = sid_len;
  for (usz i = 0; i < sid_len; i++) out[off + 35 + i] = sid[i];
  off += 35 + sid_len;
  quic_put_be16(out + off, cipher);
  out[off + 2] = 0; /* compression */
  return off + 3;
}

/* RFC 8446 4.2.1 ServerHello supported_versions: ext_data is the selected
 * version (2 bytes), no list length. type(2) ext_len(2)=2 version(2). */
static int shb_versions(u8 *buf, usz cap, usz *off) {
  u8        ext[6];
  quic_obuf out = {buf, cap, *off};
  quic_put_be16(ext, QUIC_EXT_SUPPORTED_VERSIONS);
  quic_put_be16(ext + 2, 2);
  quic_put_be16(ext + 4, QUIC_TLS13_VERSION);
  if (!quic_tls_ext_append(&out, quic_span_of(ext, 6))) return 0;
  *off = out.len;
  return 1;
}

/* RFC 8446 4.2.8 ServerHello key_share: a single KeyShareEntry, no shares
 * length. type(2) ext_len(2)=36 group(2) ke_len(2)=32 key(32). */
static int shb_key_share(u8 *buf, usz cap, usz *off, const u8 pub[32]) {
  u8        ext[40];
  quic_obuf out = {buf, cap, *off};
  quic_put_be16(ext, QUIC_EXT_KEY_SHARE);
  quic_put_be16(ext + 2, 36);
  quic_put_be16(ext + 4, QUIC_GROUP_X25519);
  quic_put_be16(ext + 6, 32);
  for (usz i = 0; i < 32; i++) ext[8 + i] = pub[i];
  if (!quic_tls_ext_append(&out, quic_span_of(ext, 40))) return 0;
  *off = out.len;
  return 1;
}

/* Append both extensions; returns the body end offset, or 0 on overflow. */
static usz shb_exts(u8 *buf, usz cap, usz off, const u8 pub[32]) {
  int ok = shb_versions(buf, cap, &off);
  ok &= shb_key_share(buf, cap, &off, pub);
  return ok ? off : 0;
}

/* Finish the extensions block and patch the handshake length. */
static usz shb_finish(u8 *buf, usz off, usz block_start) {
  usz end;
  if (off == 0) return 0;
  end = quic_tls_ext_block_finish(buf, off, block_start);
  if (end != 0) quic_hs_finish(buf, end);
  return end;
}

/* Header(4) + prefix(38 + sid_len) + extensions length(2) fit in cap. */
static int shb_fits(usz off, u8 sid_len, usz cap) {
  return off != 0 && off + 38 + sid_len + 2 <= cap;
}

int quic_shbuild_server_hello(
    const u8  random[32],
    const u8 *session_id,
    u8        sid_len,
    u16       cipher_suite,
    const u8  server_pub[32],
    u8       *out,
    usz       cap,
    usz      *out_len) {
  usz off = quic_hs_begin(out, cap, QUIC_HS_SERVER_HELLO);
  usz block_start, end;
  if (!shb_fits(off, sid_len, cap)) return 0;
  off         = shb_prefix(out, off, random, session_id, sid_len, cipher_suite);
  block_start = off;
  end = shb_finish(out, shb_exts(out, cap, off + 2, server_pub), block_start);
  if (end == 0) return 0;
  *out_len = end;
  return 1;
}
