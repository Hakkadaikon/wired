#include "transport/version/versmgr/avail.h"

#include "transport/version/version/version.h"

void quic_vers_init(quic_vers_set *s)
{
    s->n = 2;
    s->versions[0] = QUIC_VERSION_2; /* RFC 9368 5: preference order */
    s->versions[1] = QUIC_VERSION_1;
}

static int in_list(const u32 *list, usz n, u32 v)
{
    for (usz i = 0; i < n; i++)
        if (list[i] == v) return 1;
    return 0;
}

int quic_vers_supports(const quic_vers_set *s, u32 version)
{
    return in_list(s->versions, s->n, version);
}

int quic_vers_choose_compatible(const quic_vers_set *s,
                                const u32 *peer_versions, usz n, u32 *chosen)
{
    for (usz i = 0; i < s->n; i++) {
        if (in_list(peer_versions, n, s->versions[i])) {
            *chosen = s->versions[i];
            return 1;
        }
    }
    return 0;
}
