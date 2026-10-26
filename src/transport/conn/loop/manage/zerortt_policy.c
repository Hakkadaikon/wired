#include "transport/conn/loop/manage/zerortt_policy.h"

/* RFC 8446 8.1 / RFC 9001 9.2 */
int zerortt_replay_ok(int policy_safe, int ticket_first_use) {
  return policy_safe && ticket_first_use;
}
