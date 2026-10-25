#ifndef SALPN_IDNA_H
#define SALPN_IDNA_H

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"

/* RFC 6125 6.4.2 / RFC 5891 4.4: a DNS-ID or SNI value with
 * internationalized labels is compared in A-label form (the "xn--..."
 * Punycode (RFC 3492) ACE encoding), never as raw U-label Unicode, so
 * x509_san_matches' RFC 6125 6.4.1 ASCII comparison applies unchanged.
 *
 * Each label of host (UTF-8, labels split at '.') is converted on its own:
 * an all-ASCII label is copied as is, any other is a U-label and becomes
 * "xn--" + its Punycode. The IDNA2008 mapping and validity steps (RFC 5891
 * 5.3-5.4: NFC, case folding, the code point tables) are the caller's: the
 * input labels must already be valid U-labels (RFC 5895 is the
 * application-side mapping). */

/* Write host's A-label form into out and return its byte count. Returns 0
 * if host is empty or over 255 bytes, has an empty label or malformed
 * UTF-8, a label's A-label exceeds 63 octets, or the result does not fit
 * cap. */
usz salpn_idna_to_ascii(wired_span host, u8* out, usz cap);

#endif
