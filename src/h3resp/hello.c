#include "h3resp/hello.h"
#include "h3resp/resp_build.h"

/* RFC 9114 4.1 */
int quic_h3resp_hello(u8 *out, usz cap, usz *out_len)
{
    static const u8 body[] = {'h', 'e', 'l', 'l', 'o', '\n'};
    return quic_h3resp_build(200, body, sizeof body, out, cap, out_len);
}
