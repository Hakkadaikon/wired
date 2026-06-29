#include "udpsess/udpsess.h"

void quic_udpsess_init(quic_udpsess *s, quic_udp_transport *t,
                       const u8 *dcid, u8 dcid_len)
{
    usz i;
    s->t = t;
    s->active = 0;
    for (i = 0; i < QUIC_UDPSESS_PATHS; i++) {
        s->paths[i].peer_addr = 0;
        s->paths[i].peer_port = 0;
        s->paths[i].dcid = 0;
        s->paths[i].dcid_len = 0;
    }
    s->paths[0].peer_addr = t->peer_addr;
    s->paths[0].peer_port = t->peer_port;
    s->paths[0].dcid = dcid;
    s->paths[0].dcid_len = dcid_len;
}

void quic_udpsess_set_peer(quic_udpsess *s, usz path, u32 addr, u16 port)
{
    if (path >= QUIC_UDPSESS_PATHS) return;
    s->paths[path].peer_addr = addr;
    s->paths[path].peer_port = port;
}

void quic_udpsess_set_dcid(quic_udpsess *s, usz path,
                           const u8 *dcid, u8 dcid_len)
{
    if (path >= QUIC_UDPSESS_PATHS) return;
    s->paths[path].dcid = dcid;
    s->paths[path].dcid_len = dcid_len;
}

int quic_udpsess_can_migrate(const quic_udpsess *s, int new_path_validated)
{
    (void)s;
    return new_path_validated != 0; /* RFC 9000 9.3: no migration before validation */
}

/* A path may become the active send target only once validated and addressed. */
static int migrate_ok(const quic_udpsess *s, usz path, int validated)
{
    return path < QUIC_UDPSESS_PATHS && validated && s->paths[path].peer_addr;
}

int quic_udpsess_migrate(quic_udpsess *s, usz path, int new_path_validated)
{
    if (!migrate_ok(s, path, new_path_validated)) return 0;
    quic_udp_transport_connect(s->t, s->paths[path].peer_addr,
                               s->paths[path].peer_port);
    s->active = path;
    return 1;
}

int quic_udpsess_dcid_for_path(const quic_udpsess *s, usz path,
                               const u8 **dcid, u8 *len)
{
    if (path >= QUIC_UDPSESS_PATHS || !s->paths[path].dcid) return 0;
    *dcid = s->paths[path].dcid;
    *len = s->paths[path].dcid_len;
    return 1;
}
