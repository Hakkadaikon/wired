#include "tls/handshake/roles/eebuild/eebuild.h"

#include "common/bytes/util/be.h"
#include "tls/ext/salpn/negotiate.h"
#include "tls/handshake/core/tls/handshake.h"
#include "tls/handshake/core/tls/tpext.h"

/* Body = extensions<2> wrapping the ALPN extension (9 bytes for "h3", 17 for
 * "hq-interop" -- 6-byte ALPN header + 1-byte name_len + up to 10-byte name)
 * followed by the quic_transport_parameters extension. Header(4) +
 * ext_list_len(2) precede the ALPN ext and the 0x39 extension's 4-byte
 * header + tp_len. Sized for the larger (hq-interop) case so both fit. */
#define EEBUILD_ALPN_LEN 17
static int eebuild_fits(usz tp_len, usz cap) {
  return tp_len <= 0xFFFF && 4 + 2 + EEBUILD_ALPN_LEN + 4 + tp_len <= cap;
}

int quic_eebuild_encrypted_extensions(
    quic_salpn_choice alpn, quic_span transport_params, quic_obuf* out) {
  usz       off, alpn_len, ext;
  quic_obuf eob;
  if (!eebuild_fits(transport_params.n, out->cap)) return 0;
  off = quic_hs_begin(out->p, out->cap, QUIC_HS_ENCRYPTED_EXT);
  if (!quic_salpn_build_response(
          alpn, out->p + off + 2, out->cap - off - 2, &alpn_len))
    return 0; /* QUIC_SALPN_NONE or too small -- either way, nothing built */
  eob =
      quic_obuf_of(out->p + off + 2 + alpn_len, out->cap - off - 2 - alpn_len);
  ext = quic_tpext_encode(&eob, transport_params);
  /* extensions block length */
  quic_put_be16(out->p + off, (u16)(alpn_len + ext));
  out->len = off + 2 + alpn_len + ext;
  quic_hs_finish(out->p, out->len);
  return 1;
}
