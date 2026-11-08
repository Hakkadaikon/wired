#include "app/moqt/run/moqtrun_impl.h"

/* draft-23 3.7: "Grease values (Section 13) in this range are not
 * Mandatory Track Properties". */
int moqtrun_tprop_grease(u64 type, u64 caps) {
  return (caps & MOQVER_CAP_PROP_RULES) && moqctl_is_grease(type);
}

/* draft-19 2.5.1 (draft-18 2.5.1, draft-22 3.7, draft-23 3.7): "An Object
 * received with a Mandatory Track Property as an Object Property is
 * malformed". */
int moqtrun_obj_props_bad(wired_span props, u64 caps) {
  return (moqtrun_tprops_check(props, caps) & MOQTRUN_TP_MAND) != 0;
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
