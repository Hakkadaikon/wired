#include "transport/conn/lifecycle/idledrive/closesend.h"

/* RFC 9000 10.2 */
int quic_idledrive_should_close(int error_occurred, int idle_expired)
{
    return error_occurred != 0 || idle_expired != 0;
}
