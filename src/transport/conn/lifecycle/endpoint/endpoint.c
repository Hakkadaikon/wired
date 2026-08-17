#include "transport/conn/lifecycle/endpoint/endpoint.h"

void endpoint_init(endpoint* e, const u8 priv[32], const u8 dcid[8]) {
  for (usz i = 0; i < 32; i++) e->priv[i] = priv[i];
  for (usz i = 0; i < 8; i++) e->dcid[i] = dcid[i];
  wired_x25519_base(e->pub, e->priv);
  e->have_hs_keys = 0;
}

int endpoint_agree(endpoint* e, const endpoint_peer* p) {
  u8                shared[32], hs_secret[QUIC_HKDF_PRK];
  handshake_keys_in in;
  if (!wired_x25519(shared, e->priv, p->peer_pub)) return 0;
  tls_handshake_secret(shared, hs_secret);
  in.hs_secret  = hs_secret;
  in.transcript = p->transcript;
  in.is_server  = p->is_server;
  tls_handshake_keys(&in, &e->hs_keys);
  e->have_hs_keys = 1;
  return 1;
}
