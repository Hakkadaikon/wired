#include "tls/handshake/core/tls/handshake.h"

#include "common/bytes/util/be.h"

usz quic_hs_begin(u8 *out, usz cap, u8 msg_type) {
  if (cap < 4) return 0;
  out[0] = msg_type;
  out[1] = out[2] = out[3] = 0; /* length patched later */
  return 4;
}

void quic_hs_finish(u8 *out, usz total) {
  usz body = total - 4;
  out[1]   = (u8)(body >> 16);
  out[2]   = (u8)(body >> 8);
  out[3]   = (u8)body;
}

usz quic_hs_parse(const u8 *buf, usz n, u8 *type, usz *body_len) {
  usz len;
  if (n < 4) return 0;
  len = ((usz)buf[1] << 16) | ((usz)buf[2] << 8) | buf[3];
  if (4 + len > n) return 0;
  *type     = buf[0];
  *body_len = len;
  return 4;
}

/* Append the key_share extension carrying a 32-byte X25519 public key.
 * Layout: ext_type(2) ext_len(2) [share_list_len(2)?] group(2) ks_len(2) key.
 * QUIC/TLS1.3 ClientHello uses a KeyShareClientHello list; we emit a single
 * entry. For simplicity both hello types use the same single-entry form,
 * which our own parser understands (interop with real TLS is out of scope). */
static usz put_key_share(u8 *out, usz off, const u8 pub[32]) {
  quic_put_be16(out + off, QUIC_EXT_KEY_SHARE);
  quic_put_be16(out + off + 2, 36); /* ext_data length */
  quic_put_be16(out + off + 4, QUIC_GROUP_X25519);
  quic_put_be16(out + off + 6, 32); /* key_exchange length */
  for (usz i = 0; i < 32; i++) out[off + 8 + i] = pub[i];
  return off + 40;
}

/* Write legacy_version, random, and an empty legacy_session_id. */
static usz put_hello_prefix(u8 *out, usz off, const u8 random[32]) {
  quic_put_be16(out + off, 0x0303); /* legacy_version = TLS 1.2 */
  for (usz i = 0; i < 32; i++) out[off + 2 + i] = random[i];
  out[off + 34] = 0; /* legacy_session_id length 0 */
  return off + 35;
}

usz quic_hs_build_hello(
    u8 *out, usz cap, u8 msg_type, const u8 random[32], const u8 pub[32]) {
  usz off = quic_hs_begin(out, cap, msg_type);
  if (off == 0 || cap < 4 + 35 + 4 + 40) return 0;
  off = put_hello_prefix(out, off, random);
  quic_put_be16(out + off, QUIC_TLS_AES128_GCM_SHA256); /* one cipher suite */
  out[off + 2] = 0;                 /* legacy_compression_methods length 0 */
  quic_put_be16(out + off + 3, 40); /* extensions length */
  off = put_key_share(out, off + 5, pub);
  quic_hs_finish(out, off);
  return off;
}

/* Scan the extensions area for KEY_SHARE and copy its 32-byte key. The
 * fixed offset works because we build a single-cipher, single-extension
 * hello; pub lives at body + (35 + 2 + 1 + 2 + 8). */
/* The key_share extension is present and large enough at offset ks. */
static int share_present(const u8 *body, usz body_len, usz ks) {
  if (body_len < ks + 40) return 0;
  return body[ks] == 0x00 && body[ks + 1] == QUIC_EXT_KEY_SHARE;
}

int quic_hs_peer_share(const u8 *body, usz body_len, u8 pub[32]) {
  usz ks = 35 + 2 + 1 + 2; /* prefix + cipher + compression + ext_len */
  if (!share_present(body, body_len, ks)) return 0;
  for (usz i = 0; i < 32; i++) pub[i] = body[ks + 8 + i];
  return 1;
}
