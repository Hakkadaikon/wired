#include "app/http3/request/h3resp/hello.h"

#include "app/http3/request/h3resp/resp_build.h"

/* RFC 9114 4.1 */
int h3resp_hello(wired_obuf* out) {
  static const u8 body[] = {'h', 'e', 'l', 'l', 'o', '\n'};
  return h3resp_build(200, 0, wired_span_of(body, sizeof body), out);
}
