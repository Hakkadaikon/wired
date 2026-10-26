#include "app/moqt/run/moqtrun_impl.h"

static u64        moqtrun_tprop_in(wired_span props, u64 type, u64 dflt);
static wired_span moqtrun_tprop_imm(wired_span props);
static int        moqtrun_tprop_is_mand(u64 type);
static int        moqtrun_tprop_outside(u64 v, u64 lo, u64 hi);
static int moqtrun_tprop_out_of(const moqkvp* kv, u64 type, u64 lo, u64 hi);
static u32 moqtrun_tprop_flags(const moqkvp* kv);
static u32 moqtrun_tprops_scan(wired_span props);
static u64 moqtrun_tprops_code(u32 f);

/* The last varint value of type in one Property list (KVPs to the end,
 * 2.5); dflt when absent, a malformed pair ends the scan. */
static u64 moqtrun_tprop_in(wired_span props, u64 type, u64 dflt) {
  usz    off  = 0;
  u64    prev = 0, out = dflt;
  moqkvp kv;
  while (moqtrun_kvp_next(props, &off, &prev, &kv)) {
    out = moqtrun_prop_num_of(&kv, type, out);
  }
  return out;
}

/* draft-18 12.7: the Immutable Properties (0xB) value, itself a Property
 * list; empty when absent. */
static wired_span moqtrun_tprop_imm(wired_span props) {
  usz        off  = 0;
  u64        prev = 0;
  moqkvp     kv;
  wired_span out = wired_span_of(0, 0);
  while (moqtrun_kvp_next(props, &off, &prev, &kv)) {
    if (kv.type == MOQTRUN_PROP_IMMUTABLE) {
      out = kv.raw;
    }
  }
  return out;
}

/* draft-18 12.7: "processors MUST search both the mutable properties and
 * the contents of Immutable Properties"; a mutable value wins. */
u64 moqtrun_tprop(wired_span props, u64 type, u64 dflt) {
  return moqtrun_tprop_in(
      props, type, moqtrun_tprop_in(moqtrun_tprop_imm(props), type, dflt));
}

/* draft-18/19 2.5.1 (draft-22 3.7): 0x4000-0x7FFF; this hub understands
 * none. */
static int moqtrun_tprop_is_mand(u64 type) {
  return type >= 0x4000 && type <= 0x7FFF;
}

static int moqtrun_tprop_outside(u64 v, u64 lo, u64 hi) {
  return v < lo || v > hi;
}

static int moqtrun_tprop_out_of(const moqkvp* kv, u64 type, u64 lo, u64 hi) {
  return moqtrun_prop_is_num(kv, type) &&
         moqtrun_tprop_outside(kv->num, lo, hi);
}

/* draft-18 12.5: DEFAULT_PUBLISHER_GROUP_ORDER outside 1-2, 12.6:
 * DYNAMIC_GROUPS above 1 -- "MUST close the session with
 * PROTOCOL_VIOLATION". */
static u32 moqtrun_tprop_flags(const moqkvp* kv) {
  u32 bad = (u32)(moqtrun_tprop_out_of(kv, MOQTRUN_PROP_GROUP_ORDER, 1, 2) |
                  moqtrun_tprop_out_of(kv, MOQTRUN_PROP_DYNAMIC_GROUPS, 0, 1));
  return (u32)moqtrun_tprop_is_mand(kv->type) * MOQTRUN_TP_MAND |
         bad * MOQTRUN_TP_BAD;
}

static u32 moqtrun_tprops_scan(wired_span props) {
  usz    off  = 0;
  u64    prev = 0;
  u32    f    = 0;
  moqkvp kv;
  while (moqtrun_kvp_next(props, &off, &prev, &kv)) {
    f |= moqtrun_tprop_flags(&kv);
  }
  return f;
}

u32 moqtrun_tprops_check(wired_span props) {
  return moqtrun_tprops_scan(props) |
         moqtrun_tprops_scan(moqtrun_tprop_imm(props));
}

static u64 moqtrun_tprops_code(u32 f) {
  return (f & MOQTRUN_TP_BAD) ? MOQTRUN_REQ_CLOSE
                              : MOQCTL_ERR_UNSUPPORTED_EXTENSION;
}

/* A track's Track Properties the hub must not take (PUBLISH, upstream
 * SUBSCRIBE_OK): 1 with *code MOQTRUN_REQ_CLOSE for a bad value (close
 * PROTOCOL_VIOLATION), else UNSUPPORTED_EXTENSION for a Mandatory Track
 * Property (2.5.1: "MUST NOT process or forward that track"). */
int moqtrun_tprops_refused(wired_span props, u64* code) {
  u32 f = moqtrun_tprops_check(props);
  *code = moqtrun_tprops_code(f);
  return f != 0;
}
