#ifndef QUIC_ERROR_CODES_H
#define QUIC_ERROR_CODES_H

#include "common/platform/sys/syscall.h"

/* RFC 9000 20.1 transport error codes. The 0x00-0x10 range and CRYPTO_ERROR
 * (0x0100-0x01ff) are also defined in error/error.h; this file completes the
 * set with VERSION_NEGOTIATION_ERROR and adds class predicates. */

#define QUIC_EC_NO_ERROR 0x00
#define QUIC_EC_INTERNAL_ERROR 0x01
#define QUIC_EC_CONNECTION_REFUSED 0x02
#define QUIC_EC_FLOW_CONTROL_ERROR 0x03
#define QUIC_EC_STREAM_LIMIT_ERROR 0x04
#define QUIC_EC_STREAM_STATE_ERROR 0x05
#define QUIC_EC_FINAL_SIZE_ERROR 0x06
#define QUIC_EC_FRAME_ENCODING_ERROR 0x07
#define QUIC_EC_TRANSPORT_PARAMETER_ERROR 0x08
#define QUIC_EC_CONNECTION_ID_LIMIT_ERROR 0x09
#define QUIC_EC_PROTOCOL_VIOLATION 0x0a
#define QUIC_EC_INVALID_TOKEN 0x0b
#define QUIC_EC_APPLICATION_ERROR 0x0c
#define QUIC_EC_CRYPTO_BUFFER_EXCEEDED 0x0d
#define QUIC_EC_KEY_UPDATE_ERROR 0x0e
#define QUIC_EC_AEAD_LIMIT_REACHED 0x0f
#define QUIC_EC_NO_VIABLE_PATH 0x10
#define QUIC_EC_VERSION_NEGOTIATION_ERROR 0x11

/* CRYPTO_ERROR range (RFC 9000 20.1): low byte is the TLS alert. */
#define QUIC_EC_CRYPTO_LO 0x0100
#define QUIC_EC_CRYPTO_HI 0x01ff

/* GREASE reserved values have the form 31*N+27 (RFC 9000 18.1). */
#define QUIC_EC_GREASE_MOD 31
#define QUIC_EC_GREASE_REM 27

/* True if code is a defined transport error code: the 0x00-0x11 enumerated
 * range or the CRYPTO_ERROR range. */
int quic_error_is_standard(u64 code);

/* True if code is a GREASE reserved value (31*N+27). Such codes carry no
 * meaning and must be treated as a generic error if received. */
int quic_error_is_grease(u64 code);

/* True if code is an application error code: any value not in the transport
 * (standard) space. Application codes are carried in CONNECTION_CLOSE type
 * 0x1d and are defined by the application protocol (RFC 9000 20.2). */
int quic_error_is_app(u64 code);

#endif
