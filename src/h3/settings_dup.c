#include "h3/settings_dup.h"

void quic_h3_settings_seen_init(quic_h3_settings_seen *s)
{
    s->n = 0;
}

/* RFC 9114 7.2.4. 1 if id already recorded, 0 otherwise. */
static int seen(const quic_h3_settings_seen *s, u64 id)
{
    for (usz i = 0; i < s->n; i++)
        if (s->ids[i] == id) return 1;
    return 0;
}

int quic_h3_settings_mark(quic_h3_settings_seen *s, u64 id)
{
    if (s->n >= QUIC_H3_SETTINGS_SEEN_MAX) return 0;
    if (seen(s, id)) return 0;
    s->ids[s->n++] = id;
    return 1;
}
