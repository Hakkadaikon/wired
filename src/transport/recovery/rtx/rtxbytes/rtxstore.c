#include "transport/recovery/rtx/rtxbytes/rtxstore.h"

#include "common/bytes/util/bytes.h"

void rtxbytes_init(rtxbytes* st) {
  st->next = 0;
  for (usz i = 0; i < QUIC_RTXBYTES_SLOTS; i++) st->s[i].used = 0;
}

int rtxbytes_store(rtxbytes* st, u64 pn, wired_span frame) {
  rtxbytes_slot* slot;
  usz            off = 0;

  if (frame.n > QUIC_RTXBYTES_FRAME) return 0;
  slot = &st->s[st->next];
  if (!bytes_put(
          wired_mspan_of(slot->data, QUIC_RTXBYTES_FRAME), &off,
          wired_span_of(frame.p, frame.n)))
    return 0;
  slot->pn   = pn;
  slot->len  = frame.n;
  slot->used = 1;
  st->next   = (st->next + 1) % QUIC_RTXBYTES_SLOTS;
  return 1;
}

/* RFC 9002 13.3: a held slot matches when in use and its pn equals pn. */
static int slot_holds(const rtxbytes_slot* slot, u64 pn) {
  return slot->used && slot->pn == pn;
}

int rtxbytes_get(const rtxbytes* st, u64 pn, wired_span* out) {
  for (usz i = 0; i < QUIC_RTXBYTES_SLOTS; i++) {
    if (!slot_holds(&st->s[i], pn)) continue;
    *out = wired_span_of(st->s[i].data, st->s[i].len);
    return 1;
  }
  return 0;
}
