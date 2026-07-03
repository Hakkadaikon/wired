#include "tls/keys/keyupdate/initiate.h"

int quic_keyupdate_may_initiate(const quic_keyupdate_in *in) {
  return in->handshake_confirmed && in->now >= in->last_update + 3 * in->pto;
}
