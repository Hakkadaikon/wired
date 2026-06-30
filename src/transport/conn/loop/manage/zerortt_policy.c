#include "transport/conn/loop/manage/zerortt_policy.h"

/* RFC 9308 5.3 */
int quic_zerortt_safe(int is_idempotent, int replay_protected) {
  return is_idempotent || replay_protected;
}
