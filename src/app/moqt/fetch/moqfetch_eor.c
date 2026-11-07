#include "app/moqt/fetch/moqfetch_impl.h"

/* End of Range markers (11.4.4.2; draft-23 11.4.2): the take step. */

static int moqfetch_eor_group(const moqfetch_seq* s, u64 gd, u64* g);
static int moqfetch_eor_object(const moqfetch_seq* s, u64 gd, u64 od, u64* o);
static int moqfetch_eor_resolve(
    const moqfetch_seq* s, moqfetch_obj* o, u64 gd, u64 od);

/* draft-23 11.4.2.1: an End of Range after the first entry is relative
 * to the prior Object or End of Range. */
int moqfetch_eor_rel(const moqfetch_seq* s) { return s->d23 && s->have_loc; }

/* Prior Group ID plus (Ascending) or minus (Descending) Group ID Delta. */
static int moqfetch_eor_group(const moqfetch_seq* s, u64 gd, u64* g) {
  if (!s->descending) {
    return moqfetch_add(s->group, gd, g);
  }
  if (gd > s->group) {
    return MOQCTL_R_DELTA;
  }
  *g = s->group - gd;
  return MOQCTL_OK;
}

/* Same Group: prior Object ID + Object ID Delta + 1; else absolute. */
static int moqfetch_eor_object(const moqfetch_seq* s, u64 gd, u64 od, u64* o) {
  *o = od;
  if (gd) {
    return MOQCTL_OK;
  }
  return moqfetch_group_up(s->object, od, o);
}

static int moqfetch_eor_resolve(
    const moqfetch_seq* s, moqfetch_obj* o, u64 gd, u64 od) {
  o->group  = gd;
  o->object = od;
  if (!moqfetch_eor_rel(s)) {
    return MOQCTL_OK;
  }
  if (moqfetch_eor_group(s, gd, &o->group) != MOQCTL_OK) {
    return MOQCTL_R_DELTA;
  }
  return moqfetch_eor_object(s, gd, od, &o->object);
}

/* 11.4.4.2: "the Group ID and Object ID fields are present. Subgroup ID,
 * Priority and Properties are not present", and no Object Payload Length
 * follows. Before draft-23 they are the absolute Location ending the
 * range; draft-23 11.4.2.1 delta-encodes them. */
int moqfetch_take_eor(
    wired_span b, usz* at, const moqfetch_seq* s, moqfetch_obj* o) {
  u64 gd, od;
  if (!moqvi_take(b, at, &gd) || !moqvi_take(b, at, &od)) {
    return MOQCTL_INSUFFICIENT;
  }
  return moqfetch_eor_resolve(s, o, gd, od);
}
