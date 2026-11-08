#ifndef APP_MOQT_RUN_MOQTRUN_NGR_H
#define APP_MOQT_RUN_MOQTRUN_NGR_H

#include "common/platform/sys/syscall.h"

/* A request slot's NEW_GROUP_REQUEST state, beside moqtrun_types.h's. */

/** A NEW_GROUP_REQUEST the hub sent upstream in a REQUEST_UPDATE
 * (draft-18 10.2.13): outstanding while out and the track's Largest
 * Group is still group. */
typedef struct {
  /** That NEW_GROUP_REQUEST's value. */
  u64 val;
  /** The track's Largest Group when it went out (~0: none). */
  u64 group;
  /** 1 once one went out (val/group valid). */
  u8 out;
} wired_moqtrun_ngr;

#endif
