#include "tls/handshake/core/tls/master.h"
#include "tls/handshake/core/tls/schedule.h"

void quic_tls_master_secret(const u8 hs_secret[QUIC_HKDF_PRK],
                            u8 out[QUIC_HKDF_PRK])
{
    u8 zero[QUIC_HKDF_PRK] = {0};
    u8 derived[QUIC_HKDF_PRK];
    /* RFC 8446 7.1: derived = Derive-Secret(Handshake, "derived", ""). */
    quic_tls_derive_secret(hs_secret, "derived", 7, zero, 0, derived);
    /* Master Secret = HKDF-Extract(derived, 0). */
    quic_hkdf_extract(derived, QUIC_HKDF_PRK, zero, QUIC_HKDF_PRK, out);
}
