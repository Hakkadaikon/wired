#include "tls/handshake/core/tls/hsdone.h"

/* RFC 9001 4.1.1 */
int quic_hs_complete(int finished_verified, int finished_sent) {
  return finished_verified && finished_sent;
}

/* RFC 9001 4.1.1 */
int quic_hs_confirmed(
    int is_server, int handshake_done_sent, int handshake_done_received) {
  return is_server ? handshake_done_sent : handshake_done_received;
}
