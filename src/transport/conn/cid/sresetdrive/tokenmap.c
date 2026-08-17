#include "transport/conn/cid/sresetdrive/tokenmap.h"

/* RFC 9000 10.3 */
void sresetdrive_map_init(sresetdrive_map* m) { m->count = 0; }

static int cid_eq(const sresetdrive_entry* e, const u8* cid, u8 cid_len) {
  if (e->cid_len != cid_len) return 0;
  u8 d = 0;
  for (u8 i = 0; i < cid_len; i++) d |= e->cid[i] ^ cid[i];
  return d == 0;
}

static int can_add(const sresetdrive_map* m, u8 cid_len) {
  int has_room = m->count < SRESETDRIVE_CAP;
  int fits     = cid_len <= SRESETDRIVE_MAX_CID;
  return has_room & fits;
}

static void entry_set(
    sresetdrive_entry* e,
    const u8*          cid,
    u8                 cid_len,
    const u8           token[SRESETDRIVE_TOKEN]) {
  e->cid_len = cid_len;
  for (u8 i = 0; i < cid_len; i++) e->cid[i] = cid[i];
  for (u8 i = 0; i < SRESETDRIVE_TOKEN; i++) e->token[i] = token[i];
}

/* RFC 9000 10.3 */
int sresetdrive_map_add(
    sresetdrive_map* m, wired_span cid, const u8 token[SRESETDRIVE_TOKEN]) {
  if (!can_add(m, (u8)cid.n)) return 0;
  entry_set(&m->e[m->count++], cid.p, (u8)cid.n, token);
  return 1;
}

/* RFC 9000 10.3 */
int sresetdrive_map_find(
    const sresetdrive_map* m, wired_span cid, const u8** token) {
  for (usz i = 0; i < m->count; i++) {
    if (cid_eq(&m->e[i], cid.p, (u8)cid.n)) {
      *token = m->e[i].token;
      return 1;
    }
  }
  return 0;
}
