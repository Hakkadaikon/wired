#include "h3reqenc/request_headers.h"
#include "h3reqenc/pseudo_encode.h"

/* RFC 9114 4.3.1 */
int quic_h3req_enc_get(const u8 *path, usz p_len, const u8 *authority,
                       usz a_len, u8 *out, usz cap, usz *out_len)
{
    static const u8 method[] = {'G', 'E', 'T'};
    static const u8 scheme[] = {'h', 't', 't', 'p', 's'};
    return quic_h3req_enc_pseudo(method, 3, path, p_len, scheme, 5, authority,
                                 a_len, out, cap, out_len);
}
