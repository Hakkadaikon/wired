#include "transport/conn/loop/crecv/collect.h"

#include "common/bytes/util/bytes.h"
#include "transport/packet/frame/frame/frame.h"
#include "transport/packet/frame/pipeline/framewalk.h"

void quic_crecv_init(quic_crecv *s) {
  s->received_to = 0;
  for (usz i = 0; i < QUIC_CRECV_BUF; i++) s->filled[i] = 0;
}

/* RFC 9000 19.6: write one CRYPTO frame's data at its offset. Returns 0 if it
 * does not fit the fixed buffer. */
static int place(quic_crecv *s, const quic_crypto_frame *f) {
  usz end = (usz)f->offset + (usz)f->length;
  if (end > QUIC_CRECV_BUF) return 0;
  for (usz i = 0; i < (usz)f->length; i++) {
    s->buf[f->offset + i]    = f->data[i];
    s->filled[f->offset + i] = 1;
  }
  return 1;
}

/* RFC 9000 7.5: advance the contiguous prefix over newly filled bytes. */
static void advance_prefix(quic_crecv *s) {
  while (s->received_to < QUIC_CRECV_BUF && s->filled[s->received_to])
    s->received_to++;
}

/* Decode the CRYPTO frame at frame_start and place it. Returns 0 on a bad
 * decode or overflow. */
static int take_crypto(quic_crecv *s, const u8 *frame_start, usz remaining) {
  quic_crypto_frame f;
  if (quic_frame_get_crypto(frame_start, remaining, &f) == 0) return 0;
  return place(s, &f);
}

/* Handle one walked frame: place CRYPTO, skip everything else. */
static int on_frame(quic_crecv *s, u64 type, const u8 *fs, usz rem) {
  if (type != QUIC_FRAME_CRYPTO) return 1;
  return take_crypto(s, fs, rem);
}

int quic_crecv_collect(quic_crecv *s, const u8 *frames, usz len) {
  quic_framewalk it;
  u64            type;
  const u8      *fs;
  usz            rem;
  quic_framewalk_init(&it, frames, len);
  while (quic_framewalk_next(&it, &type, &fs, &rem))
    if (!on_frame(s, type, fs, rem)) return 0;
  advance_prefix(s);
  return 1;
}
