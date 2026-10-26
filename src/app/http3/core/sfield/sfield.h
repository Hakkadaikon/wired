#ifndef SFIELD_SFIELD_H
#define SFIELD_SFIELD_H

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"

/** @file
 * RFC 8941 Structured Fields, minimal subset: parsing an sf-list whose
 * members are sf-strings, and serializing one sf-string. This is what
 * WebTransport subprotocol negotiation needs for the
 * wt-available-protocols / wt-protocol header fields. Plus an sf-dictionary
 * walk (sfield_dict_next) for RFC 9218's Priority field value.
 *
 * Wire format (RFC 8941):
 *   sf-list   (SS3.1)   -- members separated by OWS "," OWS
 *   sf-string (SS3.3.3) -- DQUOTE-delimited; content is %x20-7E where
 *                          DQUOTE and backslash are escaped as \" and \\
 */

/** Iterator over the members of an sf-list held in a borrowed buffer. */
typedef struct {
  const u8* p;   /**< first byte of the list (not owned) */
  usz       n;   /**< number of bytes at p */
  usz       off; /**< current parse position */
} sfield_iter;

/** Start iterating the sf-list in `list` (borrowed, must outlive `it`).
 *
 * @param it   iterator to initialize
 * @param list the raw field value, e.g. `"foo", "bar"`
 */
void sfield_iter_init(sfield_iter* it, wired_span list);

/** Decode the next sf-string member into out (escapes resolved).
 *
 * Parameters attached to a member (";" up to the next ",") are skipped
 * and tolerated. Any member that is not an sf-string (bare token,
 * integer, ...), a bad escape, or a missing closing DQUOTE makes the
 * whole list invalid -- the caller must discard it entirely.
 *
 * @param it  iterator (advanced past the member on success)
 * @param out receives the decoded content; out->len is advanced
 * @return 1 = member produced, 0 = end of list, -1 = syntax error
 */
int sfield_next_string(sfield_iter* it, wired_obuf* out);

/** RFC 8941 3.3: the kind of a Dictionary member's value. */
#define SFIELD_OTHER 0   /**< decimal, string, token, bytes or inner list */
#define SFIELD_INTEGER 1 /**< an Integer (num, neg) */
#define SFIELD_BOOLEAN 2 /**< a Boolean (num 0 or 1) */

/** A Dictionary member's value, as far as callers read one. */
typedef struct {
  u8  kind; /**< SFIELD_OTHER / SFIELD_INTEGER / SFIELD_BOOLEAN */
  u8  neg;  /**< SFIELD_INTEGER: 1 if negative */
  u64 num;  /**< SFIELD_INTEGER magnitude, or SFIELD_BOOLEAN 0/1 */
} sfield_item;

/** RFC 8941 4.2.2: decode the next member of the sf-dictionary at it
 * (started with sfield_iter_init over the field value). The whole
 * Dictionary is validated as it is walked -- item syntax, inner lists,
 * parameters (skipped), separators, and no trailing comma -- so a -1 at any
 * member means the caller must discard every member it already took.
 *
 * @param it  iterator (advanced past the member and its separator)
 * @param key receives the member key (a view into the list)
 * @param v   receives the member value; a bare key is Boolean true
 * @return 1 = member produced, 0 = end of dictionary, -1 = syntax error
 */
int sfield_dict_next(sfield_iter* it, wired_span* key, sfield_item* v);

/** Serialize s as one sf-string (RFC 8941 SS4.1.6): wrap in DQUOTEs and
 * backslash-escape DQUOTE and backslash.
 *
 * @param buf destination
 * @param cap capacity of buf
 * @param s   content bytes; must all be %x20-7E
 * @return bytes written, or 0 if s does not fit or contains a byte an
 *         sf-string cannot represent (0x00-0x1f, 0x7f and above)
 */
usz sfield_string_encode(u8* buf, usz cap, wired_span s);

#endif
