#ifndef CVECDSA_SIGNED_H
#define CVECDSA_SIGNED_H

#include "common/platform/sys/syscall.h"

/* RFC 8446 4.4.3 signed content for the server CertificateVerify:
 * 64*0x20 + "TLS 1.3, server CertificateVerify" + 0x00 + transcript_hash(32),
 * 130 octets total. Writes it into out[130]. */
void cvecdsa_signed_content(const u8 transcript_hash[32], u8 out[130]);

#endif
