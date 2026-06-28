#include "sflight/finished_build.h"
#include "tls/handshake.h"
#include "tls/finished.h"

int quic_sflight_finished(const u8 *finished_key, const u8 *transcript_hash,
                          u8 *out, usz cap, usz *out_len)
{
    usz off;
    if (cap < 4 + QUIC_TLS_VERIFY_DATA) return 0;
    off = quic_hs_begin(out, cap, QUIC_HS_FINISHED);
    quic_tls_finished_verify_data(finished_key, transcript_hash, out + off);
    *out_len = off + QUIC_TLS_VERIFY_DATA;
    quic_hs_finish(out, *out_len);
    return 1;
}
