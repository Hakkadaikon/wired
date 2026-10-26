#ifndef APP_MOQT_CTL_MOQCTL_IMPL_H
#define APP_MOQT_CTL_MOQCTL_IMPL_H

/* Internal to the moqctl*.c pieces of this directory: shared types, macros
 * and the functions and tables more than one piece uses. Not public API. */

#include "app/moqt/ctl/moqctl.h"
#include "app/moqt/fetch/moqfetch.h"
#include "app/moqt/kvp/moqkvp.h"
#include "app/moqt/ns/moqns.h"
#include "app/moqt/tstat/moqtstat.h"
#include "app/moqt/ver/moqver.h"
#include "app/moqt/vi/moqvi.h"
#include "common/bytes/util/be.h"
#include "common/bytes/util/bytes.h"
#include "common/bytes/util/num.h"

#define MOQCTL_KNOWN_ERRS_N (sizeof MOQCTL_KNOWN_ERRS / sizeof(u64))

#define MOQCTL_KNOWN_DONE_N (sizeof MOQCTL_KNOWN_DONE / sizeof(u64))

/* Send-side code rows: code exists in a draft whose caps include cap;
 * elsewhere alt, that draft's nearest defined code, is sent. */
typedef struct {
  u64 code;
  u32 cap;
  u64 alt;
} moqctl_code_row;

#define MOQCTL_LOCFILTER_TYPES_N (sizeof MOQCTL_LOCFILTER_TYPES / sizeof(u64))

typedef int (*moqctl_rangeloc19_fn)(wired_span, usz*, moqctl_rangeloc*);

#define MOQCTL_RANGELOC19_FNS_N \
  (sizeof MOQCTL_RANGELOC19_FNS / sizeof(moqctl_rangeloc19_fn))

typedef int (*moqctl_rangeloc22_fn)(wired_span, usz*, moqctl_rangeloc*);

#define MOQCTL_RANGELOC22_FNS_N \
  (sizeof MOQCTL_RANGELOC22_FNS / sizeof(moqctl_rangeloc22_fn))

/* ===== Message Parameters (SS10.2) ===== */

/* Registry (SS10.2.x): per known Type, its encoding and, per draft
 * (indexed by MOQVER_*), the MOQCTL_PCTX_* set it may appear in -- 0 where
 * the draft does not define the Type, which then decodes like an unknown
 * one. Table-driven to keep dispatch a single lookup instead of an if/else
 * chain per type. */
typedef struct {
  u64 type;
  int enc;
  u32 ctx[MOQVER_COUNT];
  u8  lo, hi; /* allowed uint8 values; other encodings leave u8v 0 */
  u8  repeat; /* the Type MAY appear more than once (SS5.1.3) */
} moqctl_param_rule;

/* clang-format on */
#define MOQCTL_PARAM_RULE_N \
  (sizeof MOQCTL_PARAM_RULES / sizeof MOQCTL_PARAM_RULES[0])

/* Value dispatch table: one function per encoding, indexed by
 * MOQCTL_PENC_*, so the caller never branches on enc itself. */
typedef int (*moqctl_param_value_fn)(wired_span, usz*, moqctl_param*);

/* moxygen's LargestGroup (Filter Type 250, vi64 80 fa; non-spec, its
 * interop client's default SUBSCRIBE): accepted as Largest Object, the
 * nearest live-edge filter, rather than closing the session. */
#define MOQCTL_FILTER_MOXYGEN_LARGEST_GROUP 250ULL

/* ----- SWITCHING_SET_ASSIGNMENT (moqtail): five varints + [Rank] ----- */

#define MOQCTL_SSA_VIS 5

typedef int (*moqctl_param_put_fn)(wired_mspan, usz*, const moqctl_param*);

/* Largest Location Filter: Type + Location + End Group Delta, three
 * 9-byte varints at most plus one. */
#define MOQCTL_LOCFILTER_MAX 28

/* SWITCH_FROM value: two varints (9 bytes each at most) + Flags. */
#define MOQCTL_SW_VAL_MAX 19

/* SWITCHING_SET_ASSIGNMENT value: five varints + the optional Rank. */
#define MOQCTL_SSA_VAL_MAX (MOQCTL_SSA_VIS * 9 + 1)

#define MOQCTL_KNOWN_UNIMPL_N \
  (sizeof MOQCTL_KNOWN_UNIMPL / sizeof MOQCTL_KNOWN_UNIMPL[0])

#define MOQCTL_KNOWN_IMPL_N \
  (sizeof MOQCTL_KNOWN_IMPL / sizeof MOQCTL_KNOWN_IMPL[0])

/* Types the draft-19 table above does not know: one row per wire Type,
 * defined in a draft whose caps include cap, with the Type it stands for
 * and its classification. Send side always uses the draft-19 Types
 * (REQUEST_OK is sent as 0x7). */
typedef struct {
  u32 cap;
  u64 wire;
  u64 type;
  int peek;
} moqctl_type_row;

#define MOQCTL_TYPE_ROWS_N \
  (sizeof MOQCTL_TYPE_ROWS / sizeof MOQCTL_TYPE_ROWS[0])

int moqctl_u64_in(const u64* list, usz n, u64 v);
int moqctl_rangeloc_take_end_group(
    wired_span buf, usz* at, u64 start_group, u64* end_group);
int moqctl_rangeloc19_largest(moqctl_rangeloc* out);
u64 moqctl_rangeloc19_wire_type(const moqctl_rangeloc* r);
int moqctl_rangeloc22_body(
    u64 type, wired_span buf, usz* at, moqctl_rangeloc* out);
int moqctl_rngf_has_prop(u64 ptype);
int moqctl_span_take_len(wired_span buf, usz* at, u64* len);
int moqctl_bytes_take(wired_span buf, usz* at, u64 len, wired_span* out);
int moqctl_ns_take_at(wired_span buf, usz* at, moqctl_ns* ns);
const moqctl_param_rule* moqctl_param_rule_for(u64 type);
int moqctl_param_allowed_in(const moqctl_param_rule* rule, int ver, u32 ctx);
int moqctl_pv_uint8(wired_span buf, usz* at, moqctl_param* p);
int moqctl_pv_varint(wired_span buf, usz* at, moqctl_param* p);
int moqctl_pv_location(wired_span buf, usz* at, moqctl_param* p);
int moqctl_pv_bytes(wired_span buf, usz* at, moqctl_param* p);
int moqctl_pv_token(wired_span buf, usz* at, moqctl_param* p);
/* Decodes a Token structure (SS10.2.2) filling exactly v; an undecodable
 * one is MOQCTL_PARAMS_KVFMT. */
int moqctl_token_take(wired_span v, moqctl_token* t);
int moqctl_token_names_alias(const moqctl_token* t);
int moqctl_pv_locfilter(wired_span buf, usz* at, moqctl_param* p);
int moqctl_ssa_weight_ok(u64 w);
int moqctl_param_take_one(
    wired_span buf, usz* at, u32 ctx, int ver, u64 prev, moqctl_params* out);
int        moqctl_pp_uint8(wired_mspan buf, usz* at, const moqctl_param* p);
int        moqctl_pp_varint(wired_mspan buf, usz* at, const moqctl_param* p);
int        moqctl_pp_location(wired_mspan buf, usz* at, const moqctl_param* p);
int        moqctl_pp_bytes(wired_mspan buf, usz* at, const moqctl_param* p);
wired_span moqctl_residual(wired_span buf, usz at);
int        moqctl_publish_take_alias_params(
    int ver, wired_span buf, usz* at, moqctl_publish* out);
int moqctl_redirect_take(wired_span buf, usz* at, moqctl_redirect* r);

extern const moqctl_param_value_fn MOQCTL_PARAM_VALUE_FNS[10];
extern const moqctl_param_put_fn   MOQCTL_PARAM_PUT_FNS[10];

#endif
