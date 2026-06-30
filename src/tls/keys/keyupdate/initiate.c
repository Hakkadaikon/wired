#include "tls/keys/keyupdate/initiate.h"

int quic_keyupdate_may_initiate(int handshake_confirmed, u64 last_update,
                                u64 now, u64 pto)
{
    return handshake_confirmed && now >= last_update + 3 * pto;
}
