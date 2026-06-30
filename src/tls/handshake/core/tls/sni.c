#include "tls/handshake/core/tls/sni.h"

#include "common/bytes/util/be.h"
#include "common/bytes/util/bytes.h"

/* RFC 6066 3: name_type(1)=host_name + name length(2) + host. */
usz quic_tls_sni_encode(u8 *buf, usz cap, const u8 *host, usz host_len) {
  usz off = 3;
  if (host_len > 0xFFFF || off + host_len > cap) return 0;
  buf[0] = QUIC_SNI_HOST_NAME;
  quic_put_be16(buf + 1, (u16)host_len);
  quic_put_bytes(buf, cap, &off, host, host_len); /* room checked above */
  return off;
}

/* Validate the 3-byte header and read the name length into *len. */
static int sni_head(const u8 *buf, usz n, usz *len) {
  if (n < 3) return 0;
  *len = (usz)buf[1] << 8 | buf[2];
  return buf[0] == QUIC_SNI_HOST_NAME && 3 + *len <= n;
}

usz quic_tls_sni_decode(const u8 *buf, usz n, const u8 **host, usz *host_len) {
  usz len;
  if (!sni_head(buf, n, &len)) return 0;
  *host     = buf + 3;
  *host_len = len;
  return 3 + len;
}
