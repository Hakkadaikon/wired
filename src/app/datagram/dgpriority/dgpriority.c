#include "app/datagram/dgpriority/dgpriority.h"

/* RFC 9221 5.1 */
int dgpriority_valid(u8 u) { return u <= DGPRIORITY_MAX; }

/* RFC 9221 5.1: matches h3_priority_higher's convention (lower value =
 * more urgent) so a DATAGRAM's urgency and a stream's urgency compare
 * directly. */
int dgpriority_higher(u8 urg_a, u8 urg_b) { return urg_a < urg_b; }
