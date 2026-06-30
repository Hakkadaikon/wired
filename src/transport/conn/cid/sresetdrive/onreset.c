#include "transport/conn/cid/sresetdrive/onreset.h"

/* RFC 9000 10.3 */
int quic_sresetdrive_on_detected(int is_reset)
{
    return is_reset != 0;
}
