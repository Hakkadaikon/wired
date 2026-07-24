#include "tls/handshake/core/tls/ext_keyshare.h"

#include "common/bytes/util/be.h"
#include "common/bytes/util/bytes.h"

/* RFC 8446 4.2.8: type(2) ext_len(2) shares_len(2) group(2) ke_len(2) key. */

/* group -> fixed key length table (RFC 7748 for x25519, SEC1 2.3.3
 * uncompressed point for secp256r1). 0 = unrecognised group. */
static usz group_key_len(u16 group) {
  if (group == QUIC_GROUP_X25519) return 32;
  if (group == QUIC_GROUP_SECP256R1) return 65;
  return 0;
}

usz quic_tls_ext_key_share(
    u8* buf, usz cap, u16 group, const u8* pub, usz pub_len) {
  usz entry = 4 + pub_len;   /* group(2) ke_len(2) key */
  usz total = 4 + 2 + entry; /* type(2) ext_len(2) shares_len(2) entry */
  if (cap < total) return 0;
  quic_put_be16(buf, QUIC_EXT_KEY_SHARE);
  quic_put_be16(buf + 2, (u16)(2 + entry)); /* ext_data length */
  quic_put_be16(buf + 4, (u16)entry);       /* client_shares length */
  quic_put_be16(buf + 6, group);
  quic_put_be16(buf + 8, (u16)pub_len);
  for (usz i = 0; i < pub_len; i++) buf[10 + i] = pub[i];
  return total;
}

/* buf's group(2)+ke_len(2) header (n readable, already >= 4) names a
 * recognised group whose declared key length matches the group and fits in
 * n; *klen receives the key length. */
static int entry_hdr_ok(const u8* buf, usz n, usz* klen) {
  *klen = group_key_len(quic_get_be16(buf));
  if (*klen == 0 || quic_get_be16(buf + 2) != *klen) return 0;
  return 4 + *klen <= n;
}

/* The entry at buf (n readable) names a recognised group whose key fits in
 * n; *klen receives the key length. */
static int entry_ok(const u8* buf, usz n, usz* klen) {
  if (n < 4) return 0;
  return entry_hdr_ok(buf, n, klen);
}

int quic_tls_ext_key_share_parse(
    const u8* buf, usz n, u16* group, u8* pub, usz* pub_len, usz pub_cap) {
  usz klen, key = 4;
  if (!entry_ok(buf, n, &klen) || klen > pub_cap) return 0;
  *group   = quic_get_be16(buf);
  *pub_len = klen;
  return quic_take_bytes(quic_span_of(buf, n), &key, quic_mspan_of(pub, klen));
}

/* The KeyShareEntry's key_exchange length lies within avail bytes from its
 * group field; entry overall size is 4 + key length (any recognised or
 * unrecognised group - unrecognised entries are skipped, not rejected). */
static int ks_entry_fits(const u8* e, usz avail) {
  usz kelen;
  if (avail < 4) return 0;
  kelen = quic_get_be16(e + 2);
  return 4 + kelen <= avail;
}

/* The 2-byte client_shares length is present and bounds a list within n. */
static int ks_list_len(const u8* buf, usz n, usz* list) {
  if (n < 2) return 0;
  *list = quic_get_be16(buf);
  return 2 + *list <= n;
}

/* The entry at buf (avail readable) is a well-formed want_group entry whose
 * key fits in pub_cap; *klen receives the key length. */
static int ks_entry_matches(
    const u8* buf, usz avail, u16 want_group, usz pub_cap, usz* klen) {
  if (quic_get_be16(buf) != want_group) return 0;
  return entry_ok(buf, avail, klen) && *klen <= pub_cap;
}

/* Copy the matched entry's key (klen bytes, starting 4 past buf) into pub. */
static int ks_take_key(const u8* buf, usz end, usz off, usz klen, u8* pub) {
  usz key = off + 4;
  return quic_take_bytes(
      quic_span_of(buf, end), &key, quic_mspan_of(pub, klen));
}

/* Scan the KeyShareEntry list in buf[off..end) for want_group; on success
 * copy its key into pub and return 1. *off advances past each entry. */
static int ks_find_group(
    const u8* buf,
    usz*      off,
    usz       end,
    u16       want_group,
    u8*       pub,
    usz*      pub_len,
    usz       pub_cap) {
  while (ks_entry_fits(buf + *off, end - *off)) {
    usz klen;
    if (ks_entry_matches(buf + *off, end - *off, want_group, pub_cap, &klen)) {
      *pub_len = klen;
      return ks_take_key(buf, end, *off, klen, pub);
    }
    *off += 4 + quic_get_be16(buf + *off + 2);
  }
  return 0;
}

int quic_tls_ext_key_share_scan(
    const u8* buf, usz n, u16 want_group, u8* pub, usz* pub_len, usz pub_cap) {
  usz list, off = 2;
  if (!ks_list_len(buf, n, &list)) return 0;
  return ks_find_group(buf, &off, 2 + list, want_group, pub, pub_len, pub_cap);
}
