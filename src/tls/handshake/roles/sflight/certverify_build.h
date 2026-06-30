#ifndef QUIC_SFLIGHT_CERTVERIFY_BUILD_H
#define QUIC_SFLIGHT_CERTVERIFY_BUILD_H

#include "common/platform/sys/syscall.h"

/* RFC 8446 4.4.3: build the server CertificateVerify message (type 0x0f).
 * Signs (Ed25519, scheme 0x0807) the content 64*0x20 + "TLS 1.3, server
 * CertificateVerify" + 0x00 + transcript_hash, using the 32-byte private key
 * seed. Writes scheme(2) + signature<2> into the handshake message at out (cap
 * total) and sets *out_len. Returns 1, or 0 if it does not fit. */
int quic_sflight_certificate_verify(const u8 seed[32],
                                    const u8 *transcript_hash,
                                    u8 *out, usz cap, usz *out_len);

#endif
