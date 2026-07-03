#include "tls/handshake/core/tls/sni.h"

#include "common/bytes/util/be.h"
#include "common/bytes/util/bytes.h"

/* RFC 6066 3: name_type(1)=host_name + name length(2) + host. */
usz quic_tls_sni_encode(quic_obuf *out, quic_span host) {
  usz off = 3;
  if (host.n > 0xFFFF || off + host.n > out->cap) return 0;
  out->p[0] = QUIC_SNI_HOST_NAME;
  quic_put_be16(out->p + 1, (u16)host.n);
  quic_put_bytes(out->p, out->cap, &off, host.p, host.n); /* room checked above */
  out->len = off;
  return off;
}

/* Validate the 3-byte header and read the name length into *len. */
static int sni_head(quic_span buf, usz *len) {
  if (buf.n < 3) return 0;
  *len = (usz)buf.p[1] << 8 | buf.p[2];
  return buf.p[0] == QUIC_SNI_HOST_NAME && 3 + *len <= buf.n;
}

usz quic_tls_sni_decode(quic_span buf, quic_span *host) {
  usz len;
  if (!sni_head(buf, &len)) return 0;
  *host = quic_span_of(buf.p + 3, len);
  return 3 + len;
}
