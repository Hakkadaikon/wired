#include "transport/conn/loop/manage/zerortt_policy.h"

/* RFC 9308 5.3 */
int quic_zerortt_safe(int is_idempotent, int replay_protected) {
  return is_idempotent || replay_protected;
}

/* RFC 8446 8.1 / RFC 9001 9.2 */
int quic_zerortt_replay_ok(int policy_safe, int ticket_first_use) {
  return policy_safe && ticket_first_use;
}
