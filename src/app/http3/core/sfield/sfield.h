#ifndef QUIC_SFIELD_SFIELD_H
#define QUIC_SFIELD_SFIELD_H

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"

/** @file
 * RFC 8941 Structured Fields, minimal subset: parsing an sf-list whose
 * members are sf-strings, and serializing one sf-string. This is what
 * WebTransport subprotocol negotiation needs for the
 * wt-available-protocols / wt-protocol header fields.
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
} quic_sfield_iter;

/** Start iterating the sf-list in `list` (borrowed, must outlive `it`).
 *
 * @param it   iterator to initialize
 * @param list the raw field value, e.g. `"foo", "bar"`
 */
void quic_sfield_iter_init(quic_sfield_iter* it, quic_span list);

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
int quic_sfield_next_string(quic_sfield_iter* it, quic_obuf* out);

/** Serialize s as one sf-string (RFC 8941 SS4.1.6): wrap in DQUOTEs and
 * backslash-escape DQUOTE and backslash.
 *
 * @param buf destination
 * @param cap capacity of buf
 * @param s   content bytes; must all be %x20-7E
 * @return bytes written, or 0 if s does not fit or contains a byte an
 *         sf-string cannot represent (0x00-0x1f, 0x7f and above)
 */
usz quic_sfield_string_encode(u8* buf, usz cap, quic_span s);

#endif
