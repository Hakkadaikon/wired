#include "transport/packet/protect/hp/hpapply.h"

/* RFC 9001 5.4.1 */
void hp_protect_pn(u8* pn, usz pn_len, const u8* mask) {
  for (usz i = 0; i < pn_len; i++) {
    pn[i] ^= mask[1 + i];
  }
}
