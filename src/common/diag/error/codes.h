#ifndef ERROR_CODES_H
#define ERROR_CODES_H

#include "common/platform/sys/syscall.h"

/* RFC 9000 20.1 transport error codes. The 0x00-0x10 range and CRYPTO_ERROR
 * (0x0100-0x01ff) are also defined in error/error.h; this file completes the
 * set with VERSION_NEGOTIATION_ERROR and adds class predicates. */

#define EC_NO_ERROR 0x00
#define EC_INTERNAL_ERROR 0x01
#define EC_CONNECTION_REFUSED 0x02
#define EC_FLOW_CONTROL_ERROR 0x03
#define EC_STREAM_LIMIT_ERROR 0x04
#define EC_STREAM_STATE_ERROR 0x05
#define EC_FINAL_SIZE_ERROR 0x06
#define EC_FRAME_ENCODING_ERROR 0x07
#define EC_TRANSPORT_PARAMETER_ERROR 0x08
#define EC_CONNECTION_ID_LIMIT_ERROR 0x09
#define EC_PROTOCOL_VIOLATION 0x0a
#define EC_INVALID_TOKEN 0x0b
#define EC_APPLICATION_ERROR 0x0c
#define EC_CRYPTO_BUFFER_EXCEEDED 0x0d
#define EC_KEY_UPDATE_ERROR 0x0e
#define EC_AEAD_LIMIT_REACHED 0x0f
#define EC_NO_VIABLE_PATH 0x10
#define EC_VERSION_NEGOTIATION_ERROR 0x11

/* CRYPTO_ERROR range (RFC 9000 20.1): low byte is the TLS alert. */
#define EC_CRYPTO_LO 0x0100
#define EC_CRYPTO_HI 0x01ff

/* RFC 6066 3 / RFC 8446 B.2. TLS alert sent (or that would be sent) when a
 * server does not recognize the server_name offered in the ClientHello's
 * server_name extension. Pass to err_crypto() to build the matching
 * CRYPTO_ERROR code. */
#define TLS_ALERT_UNRECOGNIZED_NAME 112

/* GREASE reserved values have the form 31*N+27 (RFC 9000 18.1). */
#define EC_GREASE_MOD 31
#define EC_GREASE_REM 27

/* True if code is a defined transport error code: the 0x00-0x11 enumerated
 * range or the CRYPTO_ERROR range. */
int error_is_standard(u64 code);

/* True if code is a GREASE reserved value (31*N+27). Such codes carry no
 * meaning and must be treated as a generic error if received. */
int error_is_grease(u64 code);

/* True if code is an application error code: any value not in the transport
 * (standard) space. Application codes are carried in CONNECTION_CLOSE type
 * 0x1d and are defined by the application protocol (RFC 9000 20.2). */
int error_is_app(u64 code);

#endif
