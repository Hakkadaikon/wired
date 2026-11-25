#include "app/http3/server/srvrun/srvrun_impl.h"

static void srvrun_dgring_counts(wired_srvrun_env* env, usz* cnt);
static usz  srvrun_dgring_victim(wired_srvrun_env* env, int slot);

/* cnt[k] = entries queued for connection slot k. */
static void srvrun_dgring_counts(wired_srvrun_env* env, usz* cnt) {
  for (usz i = 0; i < env->dgring_n; i++) {
    cnt[srvrun_dgring_at(env, i)->conn_slot]++;
  }
}

/* The oldest entry of a connection holding more entries than slot does;
 * dgring_n when none. */
static usz srvrun_dgring_victim(wired_srvrun_env* env, int slot) {
  usz cnt[WIRED_CONNTABLE_CAP] = {0};
  usz i                        = 0;
  srvrun_dgring_counts(env, cnt);
  while (i < env->dgring_n &&
         cnt[srvrun_dgring_at(env, i)->conn_slot] <= cnt[slot]) {
    i++;
  }
  return i;
}

/* RFC 9221 1 (best-effort): drops the oldest entry of a connection holding
 * more of the ring than slot, so one whose window never reopens (a dead
 * peer, until the idle timeout) cannot hold the ring, while its own pushes
 * cannot evict a lighter connection's entries. Urgency is ignored: the
 * stalest entry is the one least worth sending, and a held connection's
 * entries are the stalest whatever their urgency. 0 when none qualifies. */
int srvrun_dgring_evict(wired_srvrun_env* env, int slot) {
  usz i = srvrun_dgring_victim(env, slot);
  if (i == env->dgring_n) {
    return 0;
  }
  srvrun_dgring_remove(env, i);
  env->wt_usage.datagrams_evicted++;
  return 1;
}
