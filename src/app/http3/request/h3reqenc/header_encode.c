#include "app/http3/request/h3reqenc/header_encode.h"

#include "app/qpack/qpack/literal.h"

/* RFC 9204 4.5.6 */
int quic_h3req_enc_header(
    const u8 *name,
    usz       n_len,
    const u8 *value,
    usz       v_len,
    u8       *out,
    usz       cap,
    usz      *out_len) {
  quic_qpack_field f = {quic_span_of(name, n_len), quic_span_of(value, v_len)};
  usz n = quic_qpack_literal_name_encode(quic_mspan_of(out, cap), 0, &f);
  if (!n) return 0;
  *out_len = n;
  return 1;
}
