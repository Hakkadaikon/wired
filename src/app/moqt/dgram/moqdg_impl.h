#ifndef APP_MOQT_DGRAM_MOQDG_IMPL_H
#define APP_MOQT_DGRAM_MOQDG_IMPL_H

/* Internal to the moqdg*.c pieces of this directory: shared types, macros
 * and the functions and tables more than one piece uses. Not public API. */

#include "app/moqt/dgram/moqdg.h"
#include "app/moqt/vi/moqvi.h"
#include "common/bytes/util/bytes.h"

int moqdg_type_props(u64 t);
int moqdg_type_zero_oid(u64 t);
int moqdg_type_default_prio(u64 t);
int moqdg_type_status(u64 t);
int moqdg_props_status_ok(const moqdg_obj* o);
int moqdg_take_head(wired_span buf, usz* at, moqdg_obj* o);
int moqdg_take_rest(wired_span buf, usz* at, moqdg_obj* o);
int moqdg_put_valid(const moqdg_obj* o);
int moqdg_put_body(wired_mspan buf, usz* at, const moqdg_obj* o);

#endif
