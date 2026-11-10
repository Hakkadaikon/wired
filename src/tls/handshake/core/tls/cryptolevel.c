#include "tls/handshake/core/tls/cryptolevel.h"

/* RFC 9001 4.1.3 */
int cryptolevel_unconsumed_on_promote(u64 received_to, u64 read_upto) {
  return received_to > read_upto;
}
