#ifndef TLS_KEYUPDATE_REJECT_H
#define TLS_KEYUPDATE_REJECT_H

#include "common/platform/sys/syscall.h"

/* RFC 9001 6: QUIC replaces the TLS KeyUpdate message with its own frame-
 * level key update mechanism (RFC 9001 6.1, driven by tls/keys/keyupdate).
 * An endpoint must not send a TLS KeyUpdate handshake message and must
 * treat receiving one as a connection error of type 0x010a
 * (unexpected_message, RFC 8446 B.2 alert 10). */

/* RFC 8446 B.3: the TLS handshake message type for KeyUpdate. */
#define HS_KEY_UPDATE 24

/* 1 if msg_type is the TLS KeyUpdate message and must be rejected. */
int tls_keyupdate_is_forbidden(u8 msg_type);

/* The CRYPTO_ERROR code (0x010a) to close the connection with when a TLS
 * KeyUpdate message is received. */
u64 tls_keyupdate_reject_code(void);

#endif
