#include "transport/conn/cid/sresetdrive/tokenmap.h"

/* RFC 9000 10.3 */
void quic_sresetdrive_map_init(quic_sresetdrive_map *m)
{
    m->count = 0;
}

static int cid_eq(const quic_sresetdrive_entry *e,
                  const u8 *cid, u8 cid_len)
{
    if (e->cid_len != cid_len) return 0;
    u8 d = 0;
    for (u8 i = 0; i < cid_len; i++) d |= e->cid[i] ^ cid[i];
    return d == 0;
}

static int can_add(const quic_sresetdrive_map *m, u8 cid_len)
{
    int has_room = m->count < QUIC_SRESETDRIVE_CAP;
    int fits = cid_len <= QUIC_SRESETDRIVE_MAX_CID;
    return has_room & fits;
}

static void entry_set(quic_sresetdrive_entry *e,
                      const u8 *cid, u8 cid_len,
                      const u8 token[QUIC_SRESETDRIVE_TOKEN])
{
    e->cid_len = cid_len;
    for (u8 i = 0; i < cid_len; i++) e->cid[i] = cid[i];
    for (u8 i = 0; i < QUIC_SRESETDRIVE_TOKEN; i++) e->token[i] = token[i];
}

/* RFC 9000 10.3 */
int quic_sresetdrive_map_add(quic_sresetdrive_map *m,
                             const u8 *cid, u8 cid_len,
                             const u8 token[QUIC_SRESETDRIVE_TOKEN])
{
    if (!can_add(m, cid_len)) return 0;
    entry_set(&m->e[m->count++], cid, cid_len, token);
    return 1;
}

/* RFC 9000 10.3 */
int quic_sresetdrive_map_find(const quic_sresetdrive_map *m,
                              const u8 *cid, u8 cid_len,
                              const u8 **token)
{
    for (usz i = 0; i < m->count; i++) {
        if (cid_eq(&m->e[i], cid, cid_len)) {
            *token = m->e[i].token;
            return 1;
        }
    }
    return 0;
}
