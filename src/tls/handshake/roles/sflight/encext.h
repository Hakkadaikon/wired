#ifndef QUIC_SFLIGHT_ENCEXT_H
#define QUIC_SFLIGHT_ENCEXT_H

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"

/* RFC 8446 4.3.1: build the server EncryptedExtensions message (type 0x08)
 * carrying a single quic_transport_parameters extension (0x39, RFC 9001 8.2)
 * around transport_params. Writes the full handshake message (msg_type +
 * 24-bit length + extensions block) into out and sets out->len. Returns 1 on
 * success, 0 if it does not fit. */
int quic_sflight_encrypted_extensions(quic_span transport_params, quic_obuf *out);

#endif
