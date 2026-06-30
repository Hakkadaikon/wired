#include "transport/packet/header/packet/coalorder.h"

int quic_coalesce_short_must_be_last(u8 byte0, int is_last)
{
    if ((byte0 & 0x80) != 0) return 1; /* RFC 9000 12.2: long header, any position */
    return is_last != 0;               /* short header allowed only when last */
}
