#include "transport/conn/lifecycle/closelife/idletimeout.h"

/* Treat 0 as "no advertised limit" (largest possible), so it loses any min. */
static u64 as_limit(u64 v) { return v ? v : (u64)-1; }

/* RFC 9000 10.1 */
u64 quic_idle_effective(u64 local, u64 peer) {
  u64 l = as_limit(local), p = as_limit(peer);
  u64 m = l < p ? l : p;
  return m == (u64)-1 ? 0 : m;
}

/* RFC 9000 10.1 */
int quic_idle_expired(u64 last_activity, u64 now, u64 effective) {
  return effective != 0 && now - last_activity >= effective;
}
