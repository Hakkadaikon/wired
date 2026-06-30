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
    const u8 *transport_params, usz tp_len, u8 *out, usz cap, usz *out_len) {
  usz off, ext;
  if (!encext_fits(tp_len, cap)) return 0;
  off = quic_hs_begin(out, cap, QUIC_HS_ENCRYPTED_EXT);
  ext =
      quic_tpext_encode(out + off + 2, cap - off - 2, transport_params, tp_len);
  quic_put_be16(out + off, (u16)ext); /* extensions block length */
  *out_len = off + 2 + ext;
  quic_hs_finish(out, *out_len);
  return 1;
}
