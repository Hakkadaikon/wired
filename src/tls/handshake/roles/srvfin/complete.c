#include "tls/handshake/roles/srvfin/complete.h"

void srvfin_state_init(srvfin_state* s, keysched* sched, keyset* keys) {
  s->sched     = sched;
  s->keys      = keys;
  s->confirmed = 0;
}

/* RFC 9001 4.1.2 */
int srvfin_complete(
    srvfin_state* s, const u8* final_transcript, usz final_transcript_len) {
  const initial_keys* ap;
  if (!keysched_advance_master(
          s->sched, final_transcript, final_transcript_len))
    return 0;
  if (!keysched_get(s->sched, QUIC_KS_SERVER_AP, &ap)) return 0;
  keyset_install(s->keys, QUIC_LEVEL_ONERTT, ap);
  s->confirmed = 1;
  return 1;
}
