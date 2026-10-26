#ifndef APP_MOQT_DATA_MOQDATA_IMPL_H
#define APP_MOQT_DATA_MOQDATA_IMPL_H

/* Internal to the moqdata*.c pieces of this directory: shared types, macros
 * and the functions and tables more than one piece uses. Not public API. */

#include "app/moqt/data/moqdata.h"
#include "app/moqt/vi/moqvi.h"

/* Every field of the Object at *at but its payload bytes; *len its
 * Payload Length. seq is read, not advanced (moqdata_obj_head.c). */
int moqdata_obj_head(
    wired_span            buf,
    usz*                  at,
    const moqdata_objseq* seq,
    moqdata_obj*          out,
    u64*                  len);

#define MOQDATA_FIXED_TYPES_N \
  (sizeof MOQDATA_FIXED_TYPES / sizeof MOQDATA_FIXED_TYPES[0])

#endif
