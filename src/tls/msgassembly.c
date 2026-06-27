#include "tls/msgassembly.h"

/* RFC 9001 4.1.3 */
int quic_tls_message_complete(u64 buffered, u32 declared_len)
{
    return buffered >= (u64)declared_len + 4;
}

/* RFC 9001 4.1.3 */
u32 quic_tls_message_len(const u8 *hs_header)
{
    return ((u32)hs_header[1] << 16) | ((u32)hs_header[2] << 8) | hs_header[3];
}
