#include "tls/handshake/roles/shbuild/shbuild.h"

#include "common/bytes/util/be.h"
#include "tls/handshake/core/tls/ext_block.h"
#include "tls/handshake/core/tls/ext_versions.h"
#include "tls/handshake/core/tls/handshake.h"

/* RFC 8446 4.1.3 prefix: legacy_version(2) random(32) session_id(1+sid_len)
 * cipher_suite(2) legacy_compression_method(1). Returns the offset past it. */
static usz shb_prefix(u8* out, usz off, const quic_shbuild_in* in) {
  usz sid_len = in->session_id.n;
  quic_put_be16(out + off, 0x0303);
  for (usz i = 0; i < 32; i++) out[off + 2 + i] = in->random[i];
  out[off + 34] = (u8)sid_len;
  for (usz i = 0; i < sid_len; i++) out[off + 35 + i] = in->session_id.p[i];
  off += 35 + sid_len;
  quic_put_be16(out + off, in->cipher_suite);
  out[off + 2] = 0; /* compression */
  return off + 3;
}

/* RFC 8446 4.2.1 ServerHello supported_versions: ext_data is the selected
 * version (2 bytes), no list length. type(2) ext_len(2)=2 version(2). */
static int shb_versions(u8* buf, usz cap, usz* off) {
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
static int shb_key_share(u8* buf, usz cap, usz* off, const u8 pub[32]) {
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

/* RFC 8446 4.2.11 ServerHello pre_shared_key: ext_data is just
 * selected_identity (2 bytes). This SDK only ever accepts a single offered
 * identity, so the index is always 0. type(2) ext_len(2)=2
 * selected_identity(2)=0. */
#define QUIC_EXT_PRE_SHARED_KEY 0x0029
static int shb_psk(u8* buf, usz cap, usz* off) {
  u8        ext[6];
  quic_obuf out = {buf, cap, *off};
  quic_put_be16(ext, QUIC_EXT_PRE_SHARED_KEY);
  quic_put_be16(ext + 2, 2);
  quic_put_be16(ext + 4, 0);
  if (!quic_tls_ext_append(&out, quic_span_of(ext, 6))) return 0;
  *off = out.len;
  return 1;
}

/* Append the extensions; returns the body end offset, or 0 on overflow. RFC
 * 8446 4.2.11: pre_shared_key MUST be the last extension when present. */
static usz shb_exts(
    u8* buf, usz cap, usz off, const u8 pub[32], int psk_accepted) {
  int ok = shb_versions(buf, cap, &off);
  ok &= shb_key_share(buf, cap, &off, pub);
  ok &= !psk_accepted || shb_psk(buf, cap, &off);
  return ok ? off : 0;
}

/* Finish the extensions block and patch the handshake length. */
static usz shb_finish(u8* buf, usz off, usz block_start) {
  usz end;
  if (off == 0) return 0;
  end = quic_tls_ext_block_finish(buf, off, block_start);
  if (end != 0) quic_hs_finish(buf, end);
  return end;
}

/* Header(4) + prefix(38 + sid_len) + extensions length(2) fit in cap. */
static int shb_fits(usz off, usz sid_len, usz cap) {
  return off != 0 && off + 38 + sid_len + 2 <= cap;
}

int quic_shbuild_server_hello(const quic_shbuild_in* in, quic_obuf* out) {
  usz off = quic_hs_begin(out->p, out->cap, QUIC_HS_SERVER_HELLO);
  usz block_start, end;
  if (!shb_fits(off, in->session_id.n, out->cap)) return 0;
  off         = shb_prefix(out->p, off, in);
  block_start = off;
  end         = shb_finish(
      out->p,
      shb_exts(out->p, out->cap, off + 2, in->server_pub, in->psk_accepted),
      block_start);
  if (end == 0) return 0;
  out->len = end;
  return 1;
}
