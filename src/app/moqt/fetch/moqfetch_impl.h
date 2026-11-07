#ifndef APP_MOQT_FETCH_MOQFETCH_IMPL_H
#define APP_MOQT_FETCH_MOQFETCH_IMPL_H

/* Internal to the moqfetch*.c pieces of this directory: shared types, macros
 * and the functions and tables more than one piece uses. Not public API. */

#include "app/moqt/data/moqdata.h"
#include "app/moqt/fetch/moqfetch.h"
#include "app/moqt/vi/moqvi.h"
#include "common/bytes/util/bytes.h"
#include "common/bytes/util/num.h"

typedef int (*moqfetch_variant_take_fn)(wired_span, usz*, moqfetch_fetch*);

typedef int (*moqfetch_variant_put_fn)(
    wired_mspan, usz*, const moqfetch_fetch*);

typedef int (*moqfetch_step_fn)(
    wired_span, usz*, const moqfetch_seq*, moqfetch_obj*);

#define MOQFETCH_N(a) (sizeof(a) / sizeof((a)[0]))

typedef struct {
  const moqfetch_step_fn* steps;
  usz                     n;
  void (*note)(moqfetch_seq*, const moqfetch_obj*);
} moqfetch_kind_ops;

/* A Table 8 marker value, its kind (1 End of Range, 2 End of Group /
 * Track) and whether the stream's draft has it. */
typedef struct {
  u64 flags;
  int kind;
  int ok;
} moqfetch_mark;

/* ----- encode: the inverse of each take step ----- */

typedef int (*moqfetch_put_fn)(
    wired_mspan, usz*, const moqfetch_seq*, const moqfetch_obj*);

typedef struct {
  const moqfetch_put_fn* steps;
  usz                    n;
} moqfetch_put_ops;

int moqfetch_put_object(
    wired_mspan b, usz* at, const moqfetch_seq* s, const moqfetch_obj* o);
int moqfetch_put_eor(
    wired_mspan b, usz* at, const moqfetch_seq* s, const moqfetch_obj* o);
int moqfetch_put_end(
    wired_mspan b, usz* at, const moqfetch_seq* s, const moqfetch_obj* o);

int moqfetch_add(u64 a, u64 b, u64* out);
int moqfetch_first_ok(
    wired_span b, usz* at, const moqfetch_seq* s, moqfetch_obj* o);
int moqfetch_take_group(
    wired_span b, usz* at, const moqfetch_seq* s, moqfetch_obj* o);
int moqfetch_object_absolute(const moqfetch_seq* s, const moqfetch_obj* o);
int moqfetch_take_eor(
    wired_span b, usz* at, const moqfetch_seq* s, moqfetch_obj* o);
int moqfetch_kind(u64 flags, const moqfetch_seq* s);
int moqfetch_group_up(u64 prior, u64 d, u64* out);
int moqfetch_eor_rel(const moqfetch_seq* s);
int moqfetch_ok23_take(int ver, wired_span body, moqfetch_ok* out);

extern const moqfetch_step_fn  MOQFETCH_OBJ_STEPS[7];
extern const moqfetch_step_fn  MOQFETCH_HEAD_STEPS[7];
extern const moqfetch_kind_ops MOQFETCH_KIND_OPS[3];

#endif
