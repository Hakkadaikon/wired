#include "tls/handshake/roles/eebuild/eebuild.h"

#include "common/bytes/util/be.h"
#include "tls/ext/salpn/negotiate.h"
#include "tls/ext/tlsext/earlydata.h"
#include "tls/handshake/core/tls/handshake.h"
#include "tls/handshake/core/tls/tpext.h"

/* Body = extensions<2> wrapping the ALPN extension (6-byte header +
 * name_len(1) + the alpn_len-byte name), the quic_transport_parameters
 * extension (4-byte header + tp_len), and the early_data extension (4
 * bytes, RFC 8446 4.2.10) when accepted, after the 4-byte message header. */
#define EEBUILD_EARLY_DATA_LEN 4
static int eebuild_fits(usz alpn_len, usz tp_len, usz cap) {
  return tp_len <= 0xFFFF &&
         4 + 2 + 7 + alpn_len + 4 + tp_len + EEBUILD_EARLY_DATA_LEN <= cap;
}

/* RFC 8446 4.2.10: append the empty early_data extension at out->p+off when
 * early_data is nonzero. Returns bytes written (0 or 4). */
static usz eebuild_early_data(u8* out, usz cap, int early_data) {
  usz n;
  if (!early_data) return 0;
  tlsext_early_data_ch(out, cap, &n);
  return n;
}

int eebuild_encrypted_extensions(
    wired_span  alpn,
    wired_span  transport_params,
    int         early_data,
    wired_obuf* out) {
  usz        off, alpn_len, ext, ed;
  wired_obuf eob;
  if (!eebuild_fits(alpn.n, transport_params.n, out->cap)) return 0;
  off = hs_begin(out->p, out->cap, HS_ENCRYPTED_EXT);
  eob = obuf_of(out->p + off + 2, out->cap - off - 2);
  if (!salpn_build_response_tok(alpn, &eob))
    return 0; /* nothing negotiated or too small -- nothing built */
  alpn_len = eob.len;
  eob = obuf_of(out->p + off + 2 + alpn_len, out->cap - off - 2 - alpn_len);
  ext = tpext_encode(&eob, transport_params);
  ed  = eebuild_early_data(
      out->p + off + 2 + alpn_len + ext, out->cap - off - 2 - alpn_len - ext,
      early_data);
  /* extensions block length */
  be_put_be16(out->p + off, (u16)(alpn_len + ext + ed));
  out->len = off + 2 + alpn_len + ext + ed;
  hs_finish(out->p, out->len);
  return 1;
}
