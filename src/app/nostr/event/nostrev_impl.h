#ifndef APP_NOSTR_EVENT_NOSTREV_IMPL_H
#define APP_NOSTR_EVENT_NOSTREV_IMPL_H

/* Internal to the nostrev*.c pieces: the lexer cursor and the functions
 * more than one piece uses. Not public API. */

#include "app/nostr/event/nostrev.h"
#include "common/bytes/util/bytes.h"

/* Input cursor plus the decoded-string output buffer. */
typedef struct {
  const u8* s;
  usz       n, i;
  u8*       out;
  usz       cap, olen;
  nostrev*  ev;
  u32       seen;  /* bit per required key already parsed */
  u32       depth; /* nesting inside an ignored value */
} nostrev_lx;

typedef int (*nostrev_item)(nostrev_lx* lx);

/* Next byte (-1 at end), without / with consuming it. */
int  nostrev_peek(const nostrev_lx* lx);
int  nostrev_take(nostrev_lx* lx);
void nostrev_ws(nostrev_lx* lx);
/* Consume exactly the bytes of lit. */
int nostrev_lit(nostrev_lx* lx, const char* lit, usz n);
/* Append bytes to the decoded buffer (0 when full). */
int nostrev_out(nostrev_lx* lx, const u8* p, usz n);
/* Hex digit value or -1; fold = 0x20 also accepts A-F, 0 only a-f. */
int nostrev_hexval(u8 c, u8 fold);

/* One JSON string at the cursor, decoded into the buffer. */
int nostrev_lex_str(nostrev_lx* lx, nostrev_str* o);
/* One UTF-8 sequence (lead byte >= 0x80) copied verbatim after checking
 * it is well-formed (RFC 3629 4). */
int nostrev_utf8_seq(nostrev_lx* lx);
/* Code point -> UTF-8 into the buffer. */
int nostrev_put_cp(nostrev_lx* lx, u32 cp);
/* The bytes after a backslash. */
int nostrev_escape(nostrev_lx* lx);
/* Integer: 1..19 digits, no leading zero. */
int nostrev_lex_uint(nostrev_lx* lx, u64* v);

/* Rest of a list after its opening bracket: items split by ',' up to
 * close (whitespace allowed around every token). */
int nostrev_list(nostrev_lx* lx, int close, nostrev_item item);
/* Validate and skip any value of the subset (for an ignored key). */
int nostrev_skip(nostrev_lx* lx);
/* ws ':' ws after an object key. */
int nostrev_colon(nostrev_lx* lx);
/* The tags value. */
int nostrev_tags(nostrev_lx* lx);

#endif
