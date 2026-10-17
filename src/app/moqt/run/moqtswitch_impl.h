#ifndef APP_MOQT_RUN_MOQTSWITCH_IMPL_H
#define APP_MOQT_RUN_MOQTSWITCH_IMPL_H

/* Internal to the moqtswitch*.c pieces of this directory: shared types, macros
 * and the functions and tables more than one piece uses. Not public API. */

#include "app/moqt/run/moqtswitch.h"
#include "common/bytes/util/num.h"

/* ===================== validation (TS-9) ===================== */

/* The activating side of one check: session idx, its subscription self
 * (0 for a SUBSCRIBE) under Request ID rid on track t, and held -- a
 * subscription the session already has on t (SUBSCRIBE only). */
typedef struct {
  usz                        idx;
  const wired_moqtrun_track* t;
  const wired_moqtrun_sub*   self;
  const wired_moqtrun_sub*   held;
  u64                        rid;
} moqtsw_req;

typedef int (*moqtsw_due_fn)(
    wired_moqt_hub*, const moqtsw_ops*, wired_moqtrun_track*, usz);

typedef void (*moqtsw_end_fn)(
    wired_moqt_hub*, const moqtsw_ops*, wired_moqtrun_track*, usz);

void moqtsw_orphan(
    wired_moqt_hub* hub, const moqtsw_ops* ops, wired_moqtrun_sub* b);

const moqctl_param* moqtsw_param(const moqctl_params* params);
u64                 moqtsw_verdict(
    wired_moqt_hub*      hub,
    const moqtsw_ops*    ops,
    const moqtsw_req*    r,
    const moqctl_params* params);
int moqtsw_due(
    wired_moqt_hub* hub, const moqtsw_ops* ops, wired_moqtrun_track* t, usz si);
void moqtsw_orphan(
    wired_moqt_hub* hub, const moqtsw_ops* ops, wired_moqtrun_sub* b);
int moqtsw_visit(
    wired_moqt_hub*      hub,
    const moqtsw_ops*    ops,
    wired_moqtrun_track* t,
    usz                  si,
    u32*                 live);

extern const moqtsw_end_fn MOQTSW_END_FNS[2];

#endif
