#include "app/media/mp4frag/mp4frag.h"

#include "common/bytes/util/be.h"

/* ISO/IEC 14496-12 4.2: size(4, big-endian) + type(4). Sizes 0 and 1 are
 * legal in the standard but never produced by the sample's encoder; they
 * are refused so a fragment view can never be open-ended. */

typedef struct {
  usz start;
  usz end; /* start + size */
  u32 type;
} mp4frag_box;

static u32 mp4frag_fourcc(const char* s) {
  return ((u32)(u8)s[0] << 24) | ((u32)(u8)s[1] << 16) | ((u32)(u8)s[2] << 8) |
         (u32)(u8)s[3];
}

static int mp4frag_size_ok(u32 size, usz remaining) {
  return size >= 8 && size <= remaining;
}

/* Reads the box at *off; 0 when the header is truncated or the size is
 * unusable. On 1, *off advances past the box. */
static int mp4frag_box_take(wired_span file, usz* off, mp4frag_box* b) {
  if (file.n - *off < 8) return 0;
  u32 size = be_get_be32(file.p + *off);
  if (!mp4frag_size_ok(size, file.n - *off)) return 0;
  b->start = *off;
  b->end   = *off + size;
  b->type  = be_get_be32(file.p + *off + 4);
  *off     = b->end;
  return 1;
}

/* Boxes up to and including moov form the init segment. 0 when the file
 * ends (or breaks) before a moov. */
static int mp4frag_scan_init(wired_span file, usz* off, mp4frag_layout* out) {
  mp4frag_box b;
  while (mp4frag_box_take(file, off, &b)) {
    if (b.type != mp4frag_fourcc("moov")) continue;
    out->init = wired_span_of(file.p, b.end);
    return 1;
  }
  return 0;
}

/* 0 when mdat is not an mdat box or the fragment table is already full. */
static int mp4frag_mdat_ok(const mp4frag_box* mdat, const mp4frag_layout* out) {
  return mdat->type == mp4frag_fourcc("mdat") &&
         out->n_frags < MP4FRAG_MAX_FRAGS;
}

/* The box after a moof must be its mdat; records the pair as one
 * fragment. 0 on a missing/malformed mdat or a full table. */
static int mp4frag_take_mdat(
    wired_span file, usz* off, const mp4frag_box* moof, mp4frag_layout* out) {
  mp4frag_box mdat;
  if (!mp4frag_box_take(file, off, &mdat)) return 0;
  if (!mp4frag_mdat_ok(&mdat, out)) return 0;
  out->frags[out->n_frags++] =
      wired_span_of(file.p + moof->start, mdat.end - moof->start);
  return 1;
}

/* True when b is a moof whose mdat pairing failed (missing, malformed, or
 * the fragment table is full). */
static int mp4frag_moof_bad(
    wired_span file, usz* off, const mp4frag_box* b, mp4frag_layout* out) {
  return b->type == mp4frag_fourcc("moof") &&
         !mp4frag_take_mdat(file, off, b, out);
}

/* One step of the fragment scan: reads the next box and, if it is a
 * malformed moof pairing, signals failure. 0 to stop the scan (error),
 * 1 to continue. */
static int mp4frag_scan_frags_step(
    wired_span file, usz* off, mp4frag_layout* out) {
  mp4frag_box b;
  if (!mp4frag_box_take(file, off, &b)) return 0;
  return !mp4frag_moof_bad(file, off, &b, out);
}

/* Every moof+mdat pair after the init segment; other boxes are skipped.
 * 0 on any malformed box or pair. */
static int mp4frag_scan_frags(wired_span file, usz* off, mp4frag_layout* out) {
  while (*off < file.n) {
    if (!mp4frag_scan_frags_step(file, off, out)) return 0;
  }
  return 1;
}

int mp4frag_scan(wired_span file, mp4frag_layout* out) {
  usz off      = 0;
  out->n_frags = 0;
  if (!mp4frag_scan_init(file, &off, out)) return 0;
  if (!mp4frag_scan_frags(file, &off, out)) return 0;
  return out->n_frags != 0;
}
