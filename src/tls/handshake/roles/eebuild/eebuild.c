#include "tls/handshake/roles/eebuild/eebuild.h"

#include "common/bytes/util/be.h"
#include "tls/ext/salpn/negotiate.h"
#include "tls/handshake/core/tls/handshake.h"
#include "tls/handshake/core/tls/tpext.h"

/* Body = extensions<2> wrapping the 9-byte ALPN extension ("h3") followed by
 * the quic_transport_parameters extension. Header(4) + ext_list_len(2) precede
 * the 9-byte ALPN ext and the 0x39 extension's 4-byte header + tp_len. */
#define EEBUILD_ALPN_LEN 9
static int eebuild_fits(usz tp_len, usz cap) {
  return tp_len <= 0xFFFF && 4 + 2 + EEBUILD_ALPN_LEN + 4 + tp_len <= cap;
}

int quic_eebuild_encrypted_extensions(
    const u8 *transport_params, usz tp_len, u8 *out, usz cap, usz *out_len) {
  usz       off, alpn, ext;
  quic_obuf eob;
  if (!eebuild_fits(tp_len, cap)) return 0;
  off = quic_hs_begin(out, cap, QUIC_HS_ENCRYPTED_EXT);
  quic_salpn_build_response(out + off + 2, cap - off - 2, &alpn);
  eob = quic_obuf_of(out + off + 2 + alpn, cap - off - 2 - alpn);
  ext = quic_tpext_encode(&eob, quic_span_of(transport_params, tp_len));
  quic_put_be16(out + off, (u16)(alpn + ext)); /* extensions block length */
  *out_len = off + 2 + alpn + ext;
  quic_hs_finish(out, *out_len);
  return 1;
}
