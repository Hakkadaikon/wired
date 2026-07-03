#include "tls/handshake/core/tls/ext_keyshare.h"

#include "common/bytes/util/be.h"
#include "common/bytes/util/bytes.h"

/* RFC 8446 4.2.8: type(2) ext_len(2) shares_len(2) group(2) ke_len(2) key(32).
 */
usz quic_tls_ext_key_share(u8 *buf, usz cap, const u8 pub[32]) {
  if (cap < 42) return 0;
  quic_put_be16(buf, QUIC_EXT_KEY_SHARE);
  quic_put_be16(buf + 2, 38); /* ext_data length */
  quic_put_be16(buf + 4, 36); /* client_shares length */
  quic_put_be16(buf + 6, QUIC_GROUP_X25519);
  quic_put_be16(buf + 8, 32); /* key_exchange length */
  for (usz i = 0; i < 32; i++) buf[10 + i] = pub[i];
  return 42;
}

/* The entry names x25519 and declares a 32-byte key that fits in n. */
static int entry_ok(const u8 *buf, usz n) {
  if (n < 36) return 0;
  return ((u16)buf[0] << 8 | buf[1]) == QUIC_GROUP_X25519 &&
         ((u16)buf[2] << 8 | buf[3]) == 32;
}

int quic_tls_ext_key_share_parse(const u8 *buf, usz n, u8 pub[32]) {
  if (!entry_ok(buf, n)) return 0;
  for (usz i = 0; i < 32; i++) pub[i] = buf[4 + i];
  return 1;
}

/* The KeyShareEntry's key_exchange length lies within avail bytes from its
 * group field; entry overall size is 4 + key length. */
static int ks_entry_fits(const u8 *e, usz avail) {
  usz kelen;
  if (avail < 4) return 0;
  kelen = (usz)e[2] << 8 | e[3];
  return 4 + kelen <= avail;
}

/* The 2-byte client_shares length is present and bounds a list within n. */
static int ks_list_len(const u8 *buf, usz n, usz *list) {
  if (n < 2) return 0;
  *list = (usz)buf[0] << 8 | buf[1];
  return 2 + *list <= n;
}

/* Scan the KeyShareEntry list in buf[off..end) for an x25519 entry; on success
 * copy 32 bytes into pub and return 1. *off advances past each entry. */
static int ks_find_x25519(const u8 *buf, usz *off, usz end, u8 pub[32]) {
  while (ks_entry_fits(buf + *off, end - *off)) {
    usz key = *off + 4;
    if (entry_ok(buf + *off, end - *off))
      return quic_take_bytes(
          quic_span_of(buf, end), &key, quic_mspan_of(pub, 32));
    *off += 4 + ((usz)buf[*off + 2] << 8 | buf[*off + 3]);
  }
  return 0;
}

int quic_tls_ext_key_share_scan(const u8 *buf, usz n, u8 pub[32]) {
  usz list, off = 2;
  if (!ks_list_len(buf, n, &list)) return 0;
  return ks_find_x25519(buf, &off, 2 + list, pub);
}
