#include "tls/handshake/roles/sflight/encext.h"

#include "common/bytes/util/be.h"
#include "tls/handshake/core/tls/handshake.h"
#include "tls/handshake/core/tls/tpext.h"

/* Body = extensions<2> wrapping one quic_transport_parameters extension.
 * Header(4) + ext_list_len(2) precede the extension's 4-byte header + tp_len.
 */
static int encext_fits(usz tp_len, usz cap) {
  return tp_len <= 0xFFFF && 4 + 2 + 4 + tp_len <= cap;
}

int quic_sflight_encrypted_extensions(
    quic_span transport_params, quic_obuf* out) {
  usz       off, ext;
  quic_obuf eob;
  if (!encext_fits(transport_params.n, out->cap)) return 0;
  off = quic_hs_begin(out->p, out->cap, QUIC_HS_ENCRYPTED_EXT);
  eob = quic_obuf_of(out->p + off + 2, out->cap - off - 2);
  ext = quic_tpext_encode(&eob, transport_params);
  quic_put_be16(out->p + off, (u16)ext); /* extensions block length */
  out->len = off + 2 + ext;
  quic_hs_finish(out->p, out->len);
  return 1;
}
