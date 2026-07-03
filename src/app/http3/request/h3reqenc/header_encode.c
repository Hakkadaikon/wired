#include "app/http3/request/h3reqenc/header_encode.h"

#include "app/qpack/qpack/literal.h"

/* RFC 9204 4.5.6 */
int quic_h3req_enc_header(quic_span name, quic_span value, quic_obuf *out) {
  quic_qpack_field f = {name, value};
  usz n = quic_qpack_literal_name_encode(quic_mspan_of(out->p, out->cap), 0, &f);
  if (!n) return 0;
  out->len = n;
  return 1;
}
