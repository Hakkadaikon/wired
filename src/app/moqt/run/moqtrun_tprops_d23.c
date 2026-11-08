#include "app/moqt/run/moqtrun_impl.h"

/* draft-23 3.7: "Grease values (Section 13) in this range are not
 * Mandatory Track Properties". */
int moqtrun_tprop_grease(u64 type, u64 caps) {
  return (caps & MOQVER_CAP_PROP_RULES) && moqctl_is_grease(type);
}

/* draft-23 10.4: DEFAULT_PUBLISHER_PRIORITY "above 255, it MUST close
 * the session with MALFORMED_KEY_VALUE" (draft-22 took it as 128). */
int moqtrun_tprop_prio_bad(const moqkvp* kv, u64 caps) {
  return (caps & MOQVER_CAP_PROP_RULES) &&
         moqtrun_prop_is_num(kv, MOQTRUN_PROP_DEFAULT_PUB_PRIO) &&
         kv->num > 255;
}

/* draft-23 16.8 Table 15: the Properties this hub supports and the
 * scopes they may appear in; row 0 stands for every other Type. */
static const struct {
  u64 type;
  u32 scope;
} moqtrun_prop_rows[] = {
    {0, MOQTRUN_SCOPE_TRACK | MOQTRUN_SCOPE_OBJECT},
    {0x02, MOQTRUN_SCOPE_TRACK | MOQTRUN_SCOPE_OBJECT},
    {MOQTRUN_PROP_MAX_CACHE, MOQTRUN_SCOPE_TRACK},
    {0x06, MOQTRUN_SCOPE_TRACK | MOQTRUN_SCOPE_OBJECT},
    {MOQTRUN_PROP_IMMUTABLE, MOQTRUN_SCOPE_TRACK | MOQTRUN_SCOPE_OBJECT},
    {MOQTRUN_PROP_DEFAULT_PUB_PRIO, MOQTRUN_SCOPE_TRACK},
    {MOQTRUN_PROP_GROUP_ORDER, MOQTRUN_SCOPE_TRACK},
    {MOQTRUN_PROP_DYNAMIC_GROUPS, MOQTRUN_SCOPE_TRACK},
    {0x3C, MOQTRUN_SCOPE_OBJECT},
    {0x3E, MOQTRUN_SCOPE_OBJECT},
};

#define MOQTRUN_PROP_ROWS \
  (sizeof moqtrun_prop_rows / sizeof moqtrun_prop_rows[0])

static usz moqtrun_prop_row(u64 type) {
  for (usz i = 1; i < MOQTRUN_PROP_ROWS; i++) {
    if (moqtrun_prop_rows[i].type == type) {
      return i;
    }
  }
  return 0;
}

/* 1 when this instance of type is a second one or outside scope
 * (draft-23 8.4); *seen gathers the supported rows met so far. */
static u32 moqtrun_prop_misplaced(u64 type, u32 scope, u32* seen) {
  usz i   = moqtrun_prop_row(type);
  u32 bit = ((u32)1 << i) & ~1u;
  u32 bad = (u32)((*seen & bit) != 0) |
            (u32)((moqtrun_prop_rows[i].scope & scope) == 0);
  *seen |= bit;
  return bad;
}

static u32 moqtrun_props_misplaced_in(wired_span props, u32 scope, u32* seen) {
  usz    off  = 0;
  u64    prev = 0;
  u32    bad  = 0;
  moqkvp kv;
  while (moqtrun_kvp_next(props, &off, &prev, &kv)) {
    bad |= moqtrun_prop_misplaced(kv.type, scope, seen);
  }
  return bad;
}

/* draft-23 8.4, 12.1 items 8-9: props in scope, with its Immutable
 * Properties (10.7: one list for the count), holds a supported Property
 * twice or outside its scope -- a Malformed Track. */
int moqtrun_props_malformed(wired_span props, u64 caps, u32 scope) {
  u32 seen = 0;
  u32 bad  = moqtrun_props_misplaced_in(props, scope, &seen) |
             moqtrun_props_misplaced_in(moqtrun_tprop_imm(props), scope, &seen);
  return (caps & MOQVER_CAP_PROP_RULES) && bad;
}

/* draft-19 2.5.1 (draft-18 2.5.1, draft-22 3.7, draft-23 3.7): "An Object
 * received with a Mandatory Track Property as an Object Property is
 * malformed"; draft-23 8.4 adds a Property twice or outside its scope. */
int moqtrun_obj_props_bad(wired_span props, u64 caps) {
  return (moqtrun_tprops_check(props, caps) & MOQTRUN_TP_MAND) ||
         moqtrun_props_malformed(props, caps, MOQTRUN_SCOPE_OBJECT);
}

/* An Object of t (0: none) with Object Properties props makes t a
 * Malformed Track (moqtrun_obj_props_bad, in the draft t was published
 * in). */
int moqtrun_obj_mand(const wired_moqtrun_track* t, wired_span props) {
  return t && moqtrun_obj_props_bad(props, t->pub_caps);
}

/* t, or 0 once an Object of t with Object Properties props made it a
 * Malformed Track (moqtrun_obj_mand): flagged, the Object dropped; the
 * PUBLISH_DONE sweep ends the track (12.1). */
wired_moqtrun_track* moqtrun_obj_mand_gate(
    wired_moqtrun_track* t, wired_span props) {
  if (moqtrun_obj_mand(t, props)) {
    t->malformed = 1;
    return 0;
  }
  return t;
}
