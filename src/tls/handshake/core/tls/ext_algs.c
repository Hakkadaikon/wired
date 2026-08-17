#include "tls/handshake/core/tls/ext_algs.h"

#include "common/bytes/util/be.h"

/* RFC 8446 4.2.7: type(2) + ext_data length(2) + list length(2) + groups. */
usz quic_tls_ext_supported_groups(u8* buf, usz cap) {
  if (cap < 8) return 0;
  be_put_be16(buf, QUIC_EXT_SUPPORTED_GROUPS);
  be_put_be16(buf + 2, 4);
  be_put_be16(buf + 4, 2);
  be_put_be16(buf + 6, QUIC_GROUP_X25519);
  return 8;
}

/* RFC 8446 4.2.3: type(2) + ext_data length(2) + list length(2) + schemes. */
usz quic_tls_ext_sig_algs(u8* buf, usz cap) {
  if (cap < 12) return 0;
  be_put_be16(buf, QUIC_EXT_SIGNATURE_ALGORITHMS);
  be_put_be16(buf + 2, 8);
  be_put_be16(buf + 4, 6);
  be_put_be16(buf + 6, QUIC_SIG_ECDSA_SECP256R1_SHA256);
  be_put_be16(buf + 8, QUIC_SIG_RSA_PSS_RSAE_SHA256);
  be_put_be16(buf + 10, QUIC_SIG_ED25519);
  return 12;
}

/* The 4-byte header names signature_algorithms and its declared ext_data
 * length fits in n. */
static int sig_algs_header_ok(const u8* buf, usz n) {
  usz dlen = (usz)buf[2] << 8 | buf[3];
  return ((u16)buf[0] << 8 | buf[1]) == QUIC_EXT_SIGNATURE_ALGORITHMS &&
         4 + dlen <= n;
}

/* Header valid and the list-length field exactly accounts for ext_data. */
static int sig_algs_framed(const u8* buf, usz n) {
  usz dlen, llen;
  if (n < 6 || !sig_algs_header_ok(buf, n)) return 0;
  dlen = (usz)buf[2] << 8 | buf[3];
  llen = (usz)buf[4] << 8 | buf[5];
  return dlen == llen + 2;
}

/* Scan cnt 2-byte scheme entries starting right after the list-length field
 * for `scheme`. */
static int sig_algs_scan(const u8* buf, usz cnt, u16 scheme) {
  for (usz i = 0; i < cnt; i++)
    if (((u16)buf[6 + 2 * i] << 8 | buf[7 + 2 * i]) == scheme) return 1;
  return 0;
}

int quic_tls_ext_sig_algs_has(const u8* buf, usz n, u16 scheme) {
  usz llen;
  if (!sig_algs_framed(buf, n)) return 0;
  llen = (usz)buf[4] << 8 | buf[5];
  return (llen & 1) == 0 && sig_algs_scan(buf, llen / 2, scheme);
}
