#ifndef WIRED_PEM_PEM_H
#define WIRED_PEM_PEM_H

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"

/** @file
 * RFC 7468 2-3: textual (PEM) encoding of DER structures. A PEM text is a
 * sequence of "-----BEGIN <label>-----" / "-----END <label>-----" blocks
 * whose body is base64 (RFC 4648 4) of the DER bytes; anything outside the
 * markers (comment lines, `openssl x509 -text` dumps) is ignored. The one
 * entry point walks the text block by block so a fullchain file decodes with
 * repeated calls. */

/** Decode the next PEM block of text at or after *at.
 *
 * Scans forward from *at for a "-----BEGIN <label>-----" line, base64-decodes
 * the body up to the matching "-----END " line into der (appending at
 * der->len, RFC 4648 4: `=`/`==` padding honored, CR/LF skipped), and
 * advances *at past the END line so the following call returns the next
 * block. label receives a view of the bytes between "BEGIN " and the closing
 * dashes (e.g. "CERTIFICATE"), borrowed from text.
 *
 * der is a caller-owned output buffer (see quic_obuf_of): the caller retains
 * ownership and der->p must have room for the decoded bytes, this call only
 * appends and advances der->len, it never allocates or frees.
 *
 * @param text  the whole PEM text (borrowed; must outlive label)
 * @param at    scan cursor into text; advanced past the decoded block
 * @param label receives the block's label as a view into text
 * @param der   receives the decoded DER bytes; the callee advances der->len
 * @return 1 when a block was decoded, 0 when no BEGIN marker remains or the
 *   block is broken (invalid base64, missing END line, or der overflow). */
int wired_pem_next(quic_span text, usz *at, quic_span *label, quic_obuf *der);

#endif
