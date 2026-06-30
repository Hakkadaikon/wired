#include "tls/handshake/roles/srvfin/complete.h"

void quic_srvfin_state_init(quic_srvfin_state *s,
                            quic_keysched *sched, quic_keyset *keys)
{
    s->sched = sched;
    s->keys = keys;
    s->confirmed = 0;
}

/* RFC 9001 4.1.2 */
int quic_srvfin_complete(quic_srvfin_state *s,
                         const u8 *final_transcript, usz final_transcript_len)
{
    const quic_initial_keys *ap;
    if (!quic_keysched_advance_master(s->sched, final_transcript,
                                      final_transcript_len))
        return 0;
    if (!quic_keysched_get(s->sched, QUIC_KS_SERVER_AP, &ap))
        return 0;
    quic_keyset_install(s->keys, QUIC_LEVEL_ONERTT, ap);
    s->confirmed = 1;
    return 1;
}
