#ifndef QUIC_VERSION_DOWNGRADE_H
#define QUIC_VERSION_DOWNGRADE_H

#include "version/version.h"

/* RFC 9368 6 / RFC 9369: the server's version_information reports the
 * Negotiated Version it believes is in use. If that differs from the version
 * the client actually chose, a downgrade attack may have stripped the
 * negotiation. Returns 1 when a downgrade is suspected. */

int quic_version_downgrade_detected(u32 client_chose, u32 server_reported);

#endif
