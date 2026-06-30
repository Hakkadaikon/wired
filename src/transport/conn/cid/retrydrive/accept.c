#include "transport/conn/cid/retrydrive/accept.h"

/* RFC 9000 17.2.5.2 */
int quic_retrydrive_accept(int already_received_retry, int integrity_tag_valid)
{
    return !already_received_retry && integrity_tag_valid;
}
