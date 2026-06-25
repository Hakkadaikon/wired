#include "endpoint/endpoint.h"

void quic_endpoint_init(quic_endpoint *e, const u8 priv[32], const u8 dcid[8])
{
    for (usz i = 0; i < 32; i++) e->priv[i] = priv[i];
    for (usz i = 0; i < 8; i++) e->dcid[i] = dcid[i];
    quic_x25519_base(e->pub, e->priv);
    e->have_hs_keys = 0;
}

int quic_endpoint_agree(quic_endpoint *e, const u8 peer_pub[32],
                        const u8 *transcript, usz transcript_len, int is_server)
{
    u8 shared[32], hs_secret[QUIC_HKDF_PRK];
    quic_x25519(shared, e->priv, peer_pub);
    quic_tls_handshake_secret(shared, hs_secret);
    quic_tls_handshake_keys(hs_secret, transcript, transcript_len, is_server,
                            &e->hs_keys);
    e->have_hs_keys = 1;
    return 1;
}
