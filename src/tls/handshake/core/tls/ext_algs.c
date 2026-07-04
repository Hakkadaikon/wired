#include "tls/handshake/core/tls/ext_algs.h"

#include "common/bytes/util/be.h"

/* RFC 8446 4.2.7: type(2) + ext_data length(2) + list length(2) + groups. */
usz quic_tls_ext_supported_groups(u8* buf, usz cap) {
  if (cap < 8) return 0;
  quic_put_be16(buf, QUIC_EXT_SUPPORTED_GROUPS);
  quic_put_be16(buf + 2, 4);
  quic_put_be16(buf + 4, 2);
  quic_put_be16(buf + 6, QUIC_GROUP_X25519);
  return 8;
}

/* RFC 8446 4.2.3: type(2) + ext_data length(2) + list length(2) + schemes. */
usz quic_tls_ext_sig_algs(u8* buf, usz cap) {
  if (cap < 12) return 0;
  quic_put_be16(buf, QUIC_EXT_SIGNATURE_ALGORITHMS);
  quic_put_be16(buf + 2, 8);
  quic_put_be16(buf + 4, 6);
  quic_put_be16(buf + 6, QUIC_SIG_ECDSA_SECP256R1_SHA256);
  quic_put_be16(buf + 8, QUIC_SIG_RSA_PSS_RSAE_SHA256);
  quic_put_be16(buf + 10, QUIC_SIG_ED25519);
  return 12;
}
