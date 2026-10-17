#ifndef APP_HTTP3_REQUEST_H3REQDRIVE_REQUEST_DRIVE_IMPL_H
#define APP_HTTP3_REQUEST_H3REQDRIVE_REQUEST_DRIVE_IMPL_H

/* Internal to the request_drive*.c pieces of this directory: shared types,
 * macros and the functions and tables more than one piece uses. Not public API.
 */

#include "app/http3/core/h3/headercase.h"
#include "app/http3/core/h3/priupdate.h"
#include "app/http3/core/h3/pseudoheader.h"
#include "app/http3/core/h3conn/request.h"
#include "app/http3/request/h3reqdrive/request_drive.h"
#include "app/http3/request/h3reqdrive/request_parse.h"
#include "app/http3/request/h3reqenc/request_headers.h"
#include "app/qpack/qpack/base.h"
#include "app/qpack/qpack/error.h"
#include "app/qpack/qpack/fieldline.h"
#include "app/qpack/qpack/insertcount.h"
#include "app/qpack/qpack/literal.h"
#include "app/qpack/qpack/prefix.h"
#include "app/qpack/qpack/static_table.h"
#include "app/qpack/qpackdyn/field_decode.h"
#include "common/bytes/util/bytes.h"
#include "common/bytes/util/ct.h"

/* One recovered field line: name and value, each borrowed from the static
 * table or copied into the caller's scratch. */
typedef struct {
  const u8* name;
  usz       name_len;
  const u8* value;
  usz       value_len;
  usz scratch_used; /* scratch octets this line occupies (0 if borrowed) */
  /* RFC 9204 2.2.3 / 3.1: the line failed on a reference to no live entry
   * (a connection error), not on this decoder's own capacity */
  int ref_bad;
} rline;

/* RFC 9204 4.5.2: '1' then T=1 -- an Indexed Field Line naming a static
 * entry; every other indexed form names a dynamic one. */
#define LINE_INDEXED_STATIC 0xc0

/* Field names are short (RFC 9110 5.1's token grammar, the longest ones this
 * codebase decodes -- e.g. "wt-available-protocols" -- run well under this);
 * capping the name's share leaves the rest of scr for the value, which can
 * run much longer (e.g. a multi-entry subprotocol offer list). */
#define LITNAME_NAME_CAP 64

/* Cursor state shared by the field-line walkers below: the field section and
 * scratch buffer being walked, an offset into the section and how much
 * scratch has been consumed so far, plus the dynamic-table context (RFC 9204
 * 4.5.2/4.5.3) Indexed Field Lines resolve dynamic-table references against
 * -- dyn.table == 0 (no encoder stream seen yet) makes every dynamic
 * reference unresolvable, matching this decoder's prior static-only
 * behavior. */
typedef struct {
  wired_span  fs;
  wired_mspan scr;
  usz         off;
  usz         used;
  qdyn_src    dyn;
} rd_cursor;

#define RD_DEDICATED_N (sizeof rd_dedicated / sizeof rd_dedicated[0])

/* RFC 9204 4.5.1.2 (9204-046): resolve the section prefix's Required Insert
 * Count and Base, rejecting a Sign=1 prefix whose Base would be negative
 * (qpack_base_valid). Returns bytes consumed by the prefix with *base
 * filled, 0 if the section prefix is malformed or names an invalid Base.
 * dyn is the table this section's dynamic references (if any) resolve
 * against; 0 (no encoder stream seen yet) still resolves a Base of 0
 * correctly since ric is 0 in that case (RFC 9204 4.5.1.1's EncodedInsertCount
 * 0 always decodes to RIC 0). */
/* The Required Insert Count context a section prefix's EncodedInsertCount
 * resolves against: dyn's own insertion count, or the empty-table default
 * (0) when dyn is 0 (no encoder stream seen yet). Split out of
 * h3reqdrive_prefix_base so its own branch count stays at the CCN gate. */
/* RFC 9204 4.5.1.1: MaxEntries is the maximum capacity divided by 32. */
#define QPACK_DYN_ENTRY_SIZE_OVERHEAD 32

usz  h3reqdrive_cstr_len(const char* s);
void h3reqdrive_literal_line(
    rline* L, wired_span name, wired_mspan scr, usz vlen);
usz h3reqdrive_line_indexed(
    wired_span fs, wired_mspan scr, const qdyn_src* dyn, rline* L);
usz h3reqdrive_decode_line(
    wired_span fs, wired_mspan scr, const qdyn_src* dyn, rline* L);
int  h3reqdrive_line_name_is(const rline* L, const char* s);
void h3reqdrive_classify_line(const rline* L, wired_h3reqdrive_req* r);
int  h3reqdrive_line_ok(const rline* L);
usz  h3reqdrive_rd_dedicated_idx(wired_span name);
int  h3reqdrive_step_line(rd_cursor* cur, wired_h3reqdrive_req* r);
int  h3reqdrive_scan_lines(rd_cursor* cur, wired_h3reqdrive_req* r);
usz  h3reqdrive_prefix_base(
    wired_span fs, const qpack_dyn* dyn, u64* base, u64* ric);
int h3reqdrive_decode_sections(
    wired_span            stream_data,
    wired_span            fs,
    wired_mspan           scr,
    const qpack_dyn*      dyn,
    wired_h3reqdrive_req* r);

extern usz (*const line_forms[])(
    wired_span, wired_mspan, const qdyn_src*, rline*);
extern const char* const rd_dedicated[3];

#endif
