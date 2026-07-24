#include "tls/handshake/core/tls/cryptolevel.h"

/* RFC 9001 4.1.3 */
int quic_cryptolevel_stale_extends(u64 max_seen, u64 offset, u64 len) {
  return offset + len > max_seen;
}

/* RFC 9001 4.1.3 */
int quic_cryptolevel_unconsumed_on_promote(u64 received_to, u64 read_upto) {
  return received_to > read_upto;
}
