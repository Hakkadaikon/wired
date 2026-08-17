#include "app/datagram/datagram/dgcc.h"

int datagram_flow_controlled(void) { return 0; } /* RFC 9221 5.3 */

int datagram_congestion_controlled(void) { return 1; } /* RFC 9221 5.4 */

u64 datagram_counts_in_flight(u64 size) { return size; } /* RFC 9221 5.4 */

int datagram_ack_eliciting(void) { return 1; } /* RFC 9221 5.2 */

int datagram_retransmittable(void) { return 0; } /* RFC 9221 5.2 */
