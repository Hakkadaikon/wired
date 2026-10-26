#include "tls/handshake/core/tls/ticketversion.h"

/* RFC 9369 5: compatible is not enough -- a v1 ticket never resumes v2. */
int ticket_version_ok(u32 ticket_version, u32 current_version) {
  return ticket_version == current_version;
}
