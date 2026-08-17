#include "app/http3/request/h3reqenc/request_headers.h"

#include "app/http3/request/h3reqenc/pseudo_encode.h"

/* RFC 9114 4.3.1 */
int h3req_enc_method(
    wired_span method, const h3req_headers_in* in, wired_obuf* out) {
  static const u8 scheme[] = {'h', 't', 't', 'p', 's'};
  h3req_pseudo_in p        = {
      method, wired_span_of(scheme, 5), in->authority, in->path,
      wired_span_of(0, 0)};
  return h3req_enc_pseudo(&p, out);
}

/* RFC 9114 4.3.1 */
int h3req_enc_get(const h3req_headers_in* in, wired_obuf* out) {
  static const u8 method[] = {'G', 'E', 'T'};
  return h3req_enc_method(wired_span_of(method, 3), in, out);
}
