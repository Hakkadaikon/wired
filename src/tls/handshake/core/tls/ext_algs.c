#include "tls/handshake/core/tls/ext_algs.h"

#include "common/bytes/util/be.h"

/* RFC 8446 4.2.7: type(2) + ext_data length(2) + list length(2) + groups. */
usz tls_ext_supported_groups(u8* buf, usz cap) {
  if (cap < 8) return 0;
  be_put_be16(buf, EXT_SUPPORTED_GROUPS);
  be_put_be16(buf + 2, 4);
  be_put_be16(buf + 4, 2);
  be_put_be16(buf + 6, GROUP_X25519);
  return 8;
}

/* RFC 8446 4.2.3: type(2) + ext_data length(2) + list length(2) + schemes. */
usz tls_ext_sig_algs(u8* buf, usz cap) {
  if (cap < 12) return 0;
  be_put_be16(buf, EXT_SIGNATURE_ALGORITHMS);
  be_put_be16(buf + 2, 8);
  be_put_be16(buf + 4, 6);
  be_put_be16(buf + 6, SIG_ECDSA_SECP256R1_SHA256);
  be_put_be16(buf + 8, SIG_RSA_PSS_RSAE_SHA256);
  be_put_be16(buf + 10, SIG_ED25519);
  return 12;
}

/* The 4-byte header names `type` and its declared ext_data length fits n. */
static int ext16_header_ok(const u8* buf, usz n, u16 type) {
  usz dlen = (usz)buf[2] << 8 | buf[3];
  return ((u16)buf[0] << 8 | buf[1]) == type && 4 + dlen <= n;
}

/* Header valid and the list-length field exactly accounts for ext_data --
 * the shared shape of signature_algorithms and supported_groups (RFC 8446
 * 4.2.3/4.2.7: a 2-byte list length, then 2-byte entries). */
static int ext16_framed(const u8* buf, usz n, u16 type) {
  usz dlen, llen;
  if (n < 6 || !ext16_header_ok(buf, n, type)) return 0;
  dlen = (usz)buf[2] << 8 | buf[3];
  llen = (usz)buf[4] << 8 | buf[5];
  return dlen == llen + 2;
}

/* Scan cnt 2-byte entries starting right after the list-length field. */
static int ext16_scan(const u8* buf, usz cnt, u16 want) {
  for (usz i = 0; i < cnt; i++)
    if (((u16)buf[6 + 2 * i] << 8 | buf[7 + 2 * i]) == want) return 1;
  return 0;
}

/* `want` appears in the well-framed 2-byte-entry list extension `type`. */
static int ext16_has(const u8* buf, usz n, u16 type, u16 want) {
  usz llen;
  if (!ext16_framed(buf, n, type)) return 0;
  llen = (usz)buf[4] << 8 | buf[5];
  return (llen & 1) == 0 && ext16_scan(buf, llen / 2, want);
}

int tls_ext_sig_algs_has(const u8* buf, usz n, u16 scheme) {
  return ext16_has(buf, n, EXT_SIGNATURE_ALGORITHMS, scheme);
}

int tls_ext_groups_has(const u8* buf, usz n, u16 group) {
  return ext16_has(buf, n, EXT_SUPPORTED_GROUPS, group);
}
