#include "app/http3/server/srvfwd/srvfwd.h"

#include "common/bytes/util/bytes.h"

/* Room for rx: a slot is free (cons loaded ACQUIRE, see srvfwd.h) and the
 * payload fits one. */
static int srvfwd_room(const srvfwd_ring* r, u32 prod, const xdpframe_rx* rx) {
  u32 cons = __atomic_load_n(&r->cons, __ATOMIC_ACQUIRE);
  return prod - cons < SRVFWD_DEPTH && rx->payload_len <= XSKSETUP_FRAME_SIZE;
}

int srvfwd_push(srvfwd_ring* r, const xdpframe_rx* rx) {
  u32          prod = __atomic_load_n(&r->prod, __ATOMIC_RELAXED);
  srvfwd_slot* s    = &r->slots[prod & (SRVFWD_DEPTH - 1)];
  if (!srvfwd_room(r, prod, rx)) {
    r->drops++;
    return 0;
  }
  s->rx         = *rx;
  s->rx.payload = s->buf;
  bytes_memcpy(s->buf, rx->payload, rx->payload_len);
  __atomic_store_n(&r->prod, prod + 1, __ATOMIC_RELEASE);
  return 1;
}

const xdpframe_rx* srvfwd_peek(srvfwd_ring* r) {
  u32 cons = __atomic_load_n(&r->cons, __ATOMIC_RELAXED);
  if (__atomic_load_n(&r->prod, __ATOMIC_ACQUIRE) == cons) {
    return 0;
  }
  return &r->slots[cons & (SRVFWD_DEPTH - 1)].rx;
}

void srvfwd_pop(srvfwd_ring* r) {
  u32 cons = __atomic_load_n(&r->cons, __ATOMIC_RELAXED);
  __atomic_store_n(&r->cons, cons + 1, __ATOMIC_RELEASE);
}
