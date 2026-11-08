#ifndef APP_MOQT_RUN_MOQTRUN_RNGROW_H
#define APP_MOQT_RUN_MOQTRUN_RNGROW_H

#include "common/platform/sys/syscall.h"

/* A Range Filter row, beside moqtrun_types.h's. */

/** One flattened Range Filter Range (draft-19 10.2.10-10.2.14): the
 * (ptype, set_id[, prop_type]) triple names the parameter it came from;
 * a parameter with k Ranges takes k rows. */
typedef struct {
  u64 ptype;     /**< MOQCTL_PARAM_*_FILTER (0x25-0x29) */
  u64 prop_type; /**< 0x28/0x29 only, valid iff has_prop */
  u64 start;     /**< inclusive */
  u64 end;       /**< inclusive, valid iff has_end */
  /** The filter's one-byte SetID (10.2.10): rows of one parameter
   * share it. */
  u8 set_id;
  /** 1 when prop_type is present (0x28/0x29 filters). */
  u8 has_prop;
  /** 1 when the Range has an End (end valid); 0 = open-ended. */
  u8 has_end;
} wired_moqtrun_rngrow;

#endif
