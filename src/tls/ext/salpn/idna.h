#ifndef SALPN_IDNA_H
#define SALPN_IDNA_H

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"

/* RFC 6125 6.4.2 / RFC 5891 4.4: hostname comparison for a SNI/DNS-ID value
 * containing non-ASCII (internationalized) labels compares the A-label form
 * (the "xn--..." Punycode (RFC 3492) ACE encoding), not the raw U-label
 * Unicode text.
 *
 * This SDK's DNS-ID matching (x509_san_matches, resume_sni_
 * compatible) already operates correctly on names that are already in
 * A-label / all-ASCII form: RFC 6125 6.4.1's ASCII case-insensitive byte
 * comparison needs no Unicode-aware step to compare two "xn--..." labels or
 * two plain ASCII labels.
 *
 * What is NOT implemented: converting a raw U-label (actual Unicode
 * codepoints, e.g. UTF-8 "café.example") into its A-label ("xn--caf-
 * dma.example") per the RFC 3492 Punycode algorithm. salpn_idna_to_ascii
 * below only recognizes the already-ASCII case; a caller that hands it
 * non-ASCII input gets a clean 0 (reject), never a silently wrong
 * conversion. */

/* If host is already all-ASCII (every byte < 0x80), copies it into out
 * verbatim (the A-label / ASCII-only case needs no transformation) and
 * returns the byte count. Returns 0 if host contains any non-ASCII byte
 * (Punycode U-label -> A-label conversion is not implemented) or does not
 * fit in cap. */
usz salpn_idna_to_ascii(wired_span host, u8* out, usz cap);

#endif
