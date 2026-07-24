#include "tls/keys/keyupdate/pncheck.h"

/* RFC 9001 6.4 */
int quic_keyupdate_pn_violates(u64 new_phase_min_pn, u64 old_key_pn) {
  return old_key_pn > new_phase_min_pn;
}
