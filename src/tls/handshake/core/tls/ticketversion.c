#include "tls/handshake/core/tls/ticketversion.h"

#include "transport/version/version/compat.h"

/* RFC 9369 5 */
int quic_ticket_version_ok(u32 ticket_version, u32 current_version) {
  if (ticket_version == current_version) return 1;
  return quic_version_compatible(ticket_version, current_version);
}

/* RFC 9369 5 */
int quic_ticket_0rtt_ok(u32 ticket_version, u32 current_version) {
  return quic_version_compatible(ticket_version, current_version);
}
