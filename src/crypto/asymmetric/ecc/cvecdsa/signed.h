#ifndef CVECDSA_SIGNED_H
#define CVECDSA_SIGNED_H

#include "common/bytes/span/span.h"

/* RFC 8446 4.4.3 signed content for the server CertificateVerify:
 * 64*0x20 + "TLS 1.3, server CertificateVerify" + 0x00 + transcript_hash
 * (Hash.length: 32 or 48). Writes it into out (CVECDSA_CONTENT_MAX) and
 * returns its length (130 or 146). */
#define CVECDSA_CONTENT_MAX (98 + 48)
usz cvecdsa_signed_content(wired_span transcript_hash, u8* out);

#endif
