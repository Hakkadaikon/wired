#include "app/nostr/nip98/nip98_replay.h"

#include "common/bytes/util/bytes.h"
#include "common/bytes/util/ct.h"

static int nip98_replay_live(const nip98_replay_ent* e, u64 now);
static int nip98_replay_slot(
    const nip98_replay_ent* e, const u8 id[32], u64 now);
static usz              nip98_replay_pick(usz free, usz k, int st);
static nip98_replay_res nip98_replay_store(
    nip98_replay* rc, usz free, const u8 id[32], u64 expiry);
static u64 nip98_replay_expiry(const nip98_replay* rc, u64 created_at);

void nip98_replay_init(nip98_replay* rc, u64 window) {
  bytes_memset(rc, 0, sizeof(*rc));
  rc->window = window ? window : NIP98_WINDOW_DEFAULT;
}

/* created_at + window, saturating: a wrapped sum would expire the entry at
 * once and make the token replayable. */
static u64 nip98_replay_expiry(const nip98_replay* rc, u64 created_at) {
  u64 e = created_at + rc->window;
  return e | ((u64)0 - (u64)(e < created_at));
}

static int nip98_replay_live(const nip98_replay_ent* e, u64 now) {
  return e->used && now <= e->expiry;
}

/* 0 free, 1 live with another id, 2 live with this id. */
static int nip98_replay_slot(
    const nip98_replay_ent* e, const u8 id[32], u64 now) {
  if (!nip98_replay_live(e, now)) {
    return 0;
  }
  return 1 + (ct_diff32(e->id, id) == 0);
}

/* The first free slot seen so far (NIP98_REPLAY_CAP = none yet). */
static usz nip98_replay_pick(usz free, usz k, int st) {
  return (free == NIP98_REPLAY_CAP && st == 0) ? k : free;
}

static nip98_replay_res nip98_replay_store(
    nip98_replay* rc, usz free, const u8 id[32], u64 expiry) {
  nip98_replay_ent* e;
  if (free == NIP98_REPLAY_CAP) {
    return NIP98_REPLAY_FULL; /* never evict a live id */
  }
  e = &rc->ent[free];
  bytes_memcpy(e->id, id, 32);
  e->expiry = expiry;
  e->used   = 1;
  return NIP98_REPLAY_OK;
}

/* The whole table is scanned before inserting, so a live duplicate is
 * found even when a free slot comes first. */
nip98_replay_res nip98_replay_admit(
    nip98_replay* rc, const u8 id[32], u64 created_at, u64 now) {
  usz free = NIP98_REPLAY_CAP;
  for (usz k = 0; k < NIP98_REPLAY_CAP; k++) {
    int st = nip98_replay_slot(&rc->ent[k], id, now);
    if (st == 2) {
      return NIP98_REPLAY_SEEN;
    }
    free = nip98_replay_pick(free, k, st);
  }
  return nip98_replay_store(rc, free, id, nip98_replay_expiry(rc, created_at));
}
