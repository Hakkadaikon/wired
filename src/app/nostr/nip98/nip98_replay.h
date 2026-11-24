#ifndef APP_NOSTR_NIP98_NIP98_REPLAY_H
#define APP_NOSTR_NIP98_NIP98_REPLAY_H

/* Seen-id cache for NIP-98 tokens: a fixed table of event ids, each live
 * until created_at + window (the last second its token still passes the
 * time check). The window is fixed per cache at init and nip98_check reads
 * it from the cache, so both checks use the same value.
 *
 * Order (the caller's): nip98_check verifies the token without admitting
 * it; the caller then authorises the verified pubkey; only then does it
 * call nip98_replay_admit. Admitting before authorisation would let
 * unauthorised keys fill the table. When every slot is live, a new id is
 * refused, never admitted by evicting a live entry: eviction would let a
 * captured token be replayed. Size it >= admission rate x 2 x window.
 *
 * `now` must be the same clock as nip98_check's and must not go backwards
 * between calls on one cache. */

#include "common/platform/sys/syscall.h"

#define NIP98_WINDOW_DEFAULT 60 /* seconds (NIP-98 suggests 60) */

#ifndef NIP98_REPLAY_CAP
#define NIP98_REPLAY_CAP 256
#endif

typedef struct {
  u8  id[32];
  u64 expiry;
  u8  used;
} nip98_replay_ent;

typedef struct {
  nip98_replay_ent ent[NIP98_REPLAY_CAP];
  u64              window; /* seconds, fixed at init */
} nip98_replay;

typedef enum {
  NIP98_REPLAY_OK = 0, /* id admitted */
  NIP98_REPLAY_SEEN,   /* id already live: a replay */
  NIP98_REPLAY_FULL,   /* every slot live: refused */
} nip98_replay_res;

/* Empty cache with time window `window` seconds (0 = the default). */
void nip98_replay_init(nip98_replay* rc, u64 window);
/* Admit id of a token created at created_at: live while now <= created_at
 * + window (saturating). Entries past their expiry are free slots. */
nip98_replay_res nip98_replay_admit(
    nip98_replay* rc, const u8 id[32], u64 created_at, u64 now);

#endif
