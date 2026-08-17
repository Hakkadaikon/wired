#include "app/http3/request/h3reqenc/header_encode.h"

#include "app/qpack/qpack/literal.h"

/* RFC 9204 4.5.6 */
int h3req_enc_header(wired_span name, wired_span value, wired_obuf* out) {
  qpack_field f = {name, value};
  usz n = qpack_literal_name_encode(wired_mspan_of(out->p, out->cap), 0, &f);
  if (!n) return 0;
  out->len = n;
  return 1;
}
