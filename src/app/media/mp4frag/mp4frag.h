#ifndef MP4FRAG_H
#define MP4FRAG_H

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"

/** @file
 * Fragmented-MP4 top-level layout (ISO/IEC 14496-12 box structure): the
 * init segment (`ftyp` through `moov`) and each `moof`+`mdat` media
 * fragment as views into the caller's file bytes. No sample-table
 * parsing -- a publisher only needs the fragment boundaries. */

/** Fixed capacity: media fragments one file may hold. 64 covers a
 * 2-minute loop at the sample's 2-second fragments (16 today). */
#define MP4FRAG_MAX_FRAGS 64

/** Result of mp4frag_scan: init is `ftyp` up to and including `moov`;
 * frags[i] spans the i-th `moof` and the `mdat` that immediately follows
 * it. All views point into the scanned file. */
typedef struct {
  wired_span init;                     /**< ftyp..moov inclusive */
  wired_span frags[MP4FRAG_MAX_FRAGS]; /**< each moof+mdat pair */
  usz        n_frags;                  /**< fragments found */
} mp4frag_layout;

/** Scan file's top-level boxes into *out.
 * @param file the whole fMP4
 * @param out receives the layout (valid only when 1 is returned)
 * @return 1 on success; 0 when a box header is truncated, a box size is
 *   below 8, 1 (64-bit largesize) or 0 (to end of file), a size runs past
 *   the file, a `moof` is not immediately followed by `mdat`, no `moov`
 *   precedes the first fragment, no fragment exists, or more than
 *   MP4FRAG_MAX_FRAGS fragments exist */
int mp4frag_scan(wired_span file, mp4frag_layout* out);

#endif
