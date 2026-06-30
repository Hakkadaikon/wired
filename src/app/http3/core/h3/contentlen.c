#include "app/http3/core/h3/contentlen.h"

/* RFC 9114 4.1.2 */
int quic_h3_content_length_ok(u64 declared, u64 actual) {
  return declared == actual;
}

int quic_h3_content_length_exceeded(u64 declared, u64 received_so_far) {
  return received_so_far > declared;
}
