#include "tls/keys/kuswitch/phasebit.h"

#include "tls/keys/keyupdate/keyphase.h"

u8 quic_kuswitch_phase_bit(u64 generation)
{
    /* RFC 9001 6.2 */
    return quic_keyphase_bit(generation);
}

void quic_kuswitch_apply_phase(u8 *byte0, u64 generation)
{
    /* RFC 9001 6.2 */
    *byte0 = quic_keyphase_set(*byte0, quic_keyphase_bit(generation));
}
