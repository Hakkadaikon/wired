#include "app/http3/request/h3reqenc/request_headers.h"

#include "app/http3/request/h3reqenc/pseudo_encode.h"

/* RFC 9114 4.3.1 */
int quic_h3req_enc_method(
    quic_span method, const quic_h3req_headers_in* in, quic_obuf* out) {
  static const u8      scheme[] = {'h', 't', 't', 'p', 's'};
  quic_h3req_pseudo_in p        = {
      method, quic_span_of(scheme, 5), in->authority, in->path,
      quic_span_of(0, 0)};
  return quic_h3req_enc_pseudo(&p, out);
}

/* RFC 9114 4.3.1 */
int quic_h3req_enc_get(const quic_h3req_headers_in* in, quic_obuf* out) {
  static const u8 method[] = {'G', 'E', 'T'};
  return quic_h3req_enc_method(quic_span_of(method, 3), in, out);
}
