#include "tls/handshake/roles/srvfin/complete.h"

void srvfin_state_init(srvfin_state* s, keysched* sched, keyset* keys) {
  s->sched     = sched;
  s->keys      = keys;
  s->confirmed = 0;
}

/* Advance to Master and install the server 1-RTT keys. The advance is a
 * no-op when srvfin_early_send_keys already ran (the schedule only moves
 * forward); keysched_get is the real gate -- it fails whenever no advance
 * ever succeeded. */
static int srvfin_install_app_keys(
    srvfin_state* s, const u8* transcript, usz transcript_len) {
  const initial_keys* ap;
  (void)keysched_advance_master(s->sched, transcript, transcript_len);
  if (!keysched_get(s->sched, KS_SERVER_AP, &ap)) return 0;
  keyset_install(s->keys, LEVEL_ONERTT, ap);
  return 1;
}

/* RFC 9001 4.9 / RFC 8446 7.1 (0.5-RTT) */
int srvfin_early_send_keys(
    srvfin_state* s, const u8* transcript, usz transcript_len) {
  return srvfin_install_app_keys(s, transcript, transcript_len);
}

/* RFC 9001 4.1.2 */
int srvfin_complete(
    srvfin_state* s, const u8* final_transcript, usz final_transcript_len) {
  if (!srvfin_install_app_keys(s, final_transcript, final_transcript_len))
    return 0;
  s->confirmed = 1;
  return 1;
}
