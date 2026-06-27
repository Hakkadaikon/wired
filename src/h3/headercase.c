#include "h3/headercase.h"

/* RFC 9114 4.3. 1 if c is an uppercase ASCII letter A-Z. */
static int upper(u8 c)
{
    return c >= 'A' && c <= 'Z';
}

int quic_h3_header_name_ok(const u8 *name, usz len)
{
    for (usz i = 0; i < len; i++)
        if (upper(name[i])) return 0;
    return 1;
}
