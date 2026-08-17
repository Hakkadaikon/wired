#include "tls/handshake/core/tls/sni.h"

#include "common/bytes/util/be.h"
#include "common/bytes/util/bytes.h"

/* RFC 6066 3: name_type(1)=host_name + name length(2) + host. */
usz quic_tls_sni_encode(wired_obuf* out, wired_span host) {
  usz off = 3;
  if (host.n > 0xFFFF || off + host.n > out->cap) return 0;
  out->p[0] = QUIC_SNI_HOST_NAME;
  quic_put_be16(out->p + 1, (u16)host.n);
  quic_put_bytes(
      wired_mspan_of(out->p, out->cap), &off,
      wired_span_of(host.p, host.n)); /* room checked above */
  out->len = off;
  return off;
}

/* Validate the 3-byte header and read the name length into *len. */
static int sni_head(wired_span buf, usz* len) {
  if (buf.n < 3) return 0;
  *len = (usz)buf.p[1] << 8 | buf.p[2];
  return buf.p[0] == QUIC_SNI_HOST_NAME && 3 + *len <= buf.n;
}

usz quic_tls_sni_decode(wired_span buf, wired_span* host) {
  usz len;
  if (!sni_head(buf, &len)) return 0;
  *host = wired_span_of(buf.p + 3, len);
  return 3 + len;
}
