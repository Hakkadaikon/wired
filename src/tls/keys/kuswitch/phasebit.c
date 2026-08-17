#include "tls/keys/kuswitch/phasebit.h"

#include "tls/keys/keyupdate/keyphase.h"

u8 kuswitch_phase_bit(u64 generation) {
  /* RFC 9001 6.2 */
  return keyphase_bit(generation);
}

void kuswitch_apply_phase(u8* byte0, u64 generation) {
  /* RFC 9001 6.2 */
  *byte0 = keyphase_set(*byte0, keyphase_bit(generation));
}
