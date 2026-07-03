#include "app/http3/request/h3resp/hello.h"

#include "app/http3/request/h3resp/resp_build.h"

/* RFC 9114 4.1 */
int quic_h3resp_hello(quic_obuf *out) {
  static const u8 body[] = {'h', 'e', 'l', 'l', 'o', '\n'};
  return quic_h3resp_build(200, quic_span_of(body, sizeof body), out);
}
