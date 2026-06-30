#ifndef QUIC_PACKET_PNLEN_H
#define QUIC_PACKET_PNLEN_H

#include "common/platform/sys/syscall.h"

/* RFC 9000 17.1 / Appendix A.2: fewest bytes (1-4) to encode pn so the peer
 * can recover it given largest_acked. Returns 1, 2, 3, or 4. */
usz quic_pnlen_needed(u64 pn, u64 largest_acked);

#endif
