#include "transport/conn/loop/crecv/collect.h"

#include "common/bytes/span/span.h"
#include "common/bytes/util/bytes.h"
#include "transport/packet/frame/frame/frame.h"
#include "transport/packet/frame/pipeline/framewalk.h"

void crecv_init(crecv* s, u8* mem, usz cap) {
  s->cap         = cap;
  s->received_to = 0;
  s->overflow    = 0;
  bytes_memset(mem + cap, 0, cap);
}

/* RFC 9000 19.6: write one CRYPTO frame's data at its offset. Returns 0 if it
 * does not fit the fixed buffer. */
static int place(crecv* s, u8* mem, const crypto_frame* f) {
  usz end = (usz)f->offset + (usz)f->length;
  if (end > s->cap) {
    s->overflow = 1;
    return 0;
  }
  for (usz i = 0; i < (usz)f->length; i++) {
    mem[f->offset + i]          = f->data[i];
    mem[s->cap + f->offset + i] = 1;
  }
  return 1;
}

/* RFC 9000 7.5: advance the contiguous prefix over newly filled bytes. */
static void advance_prefix(crecv* s, const u8* mem) {
  while (s->received_to < s->cap && mem[s->cap + s->received_to]) {
    s->received_to++;
  }
}

/* Decode the CRYPTO frame at frame_start and place it. Returns 0 on a bad
 * decode or overflow. */
static int take_crypto(crecv* s, u8* mem, wired_span body) {
  crypto_frame f;
  if (frame_get_crypto(body.p, body.n, &f) == 0) {
    return 0;
  }
  return place(s, mem, &f);
}

/* Handle one walked frame: place CRYPTO, skip everything else. */
static int on_frame(crecv* s, u8* mem, u64 type, wired_span body) {
  if (type != FRAME_CRYPTO) {
    return 1;
  }
  return take_crypto(s, mem, body);
}

int crecv_collect(crecv* s, u8* mem, const u8* frames, usz len) {
  framewalk      it;
  framewalk_item fr;
  framewalk_init(&it, frames, len);
  while (framewalk_next(&it, &fr)) {
    if (!on_frame(s, mem, fr.type, wired_span_of(fr.start, fr.remaining))) {
      return 0;
    }
  }
  advance_prefix(s, mem);
  return 1;
}
