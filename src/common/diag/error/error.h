#ifndef ERROR_ERROR_H
#define ERROR_ERROR_H

#include "common/platform/sys/syscall.h"

/* RFC 9000 20.1 transport error codes, carried in CONNECTION_CLOSE (0x1c). */

#define ERR_NO_ERROR 0x00
#define ERR_INTERNAL_ERROR 0x01
#define ERR_CONNECTION_REFUSED 0x02
#define ERR_FLOW_CONTROL_ERROR 0x03
#define ERR_STREAM_LIMIT_ERROR 0x04
#define ERR_STREAM_STATE_ERROR 0x05
#define ERR_FINAL_SIZE_ERROR 0x06
#define ERR_FRAME_ENCODING_ERROR 0x07
#define ERR_TRANSPORT_PARAMETER_ERROR 0x08
#define ERR_CONNECTION_ID_LIMIT_ERROR 0x09
#define ERR_PROTOCOL_VIOLATION 0x0a
#define ERR_INVALID_TOKEN 0x0b
#define ERR_APPLICATION_ERROR 0x0c
#define ERR_CRYPTO_BUFFER_EXCEEDED 0x0d
#define ERR_KEY_UPDATE_ERROR 0x0e
#define ERR_AEAD_LIMIT_REACHED 0x0f
#define ERR_NO_VIABLE_PATH 0x10

/* CRYPTO_ERROR occupies the range 0x0100-0x01ff; the low byte is the TLS
 * alert (RFC 9000 20.1). */
#define ERR_CRYPTO_BASE 0x0100

/* Build a CRYPTO_ERROR code from a TLS alert (0..255). */
u64 err_crypto(u8 tls_alert);

/* True if code is in the CRYPTO_ERROR range. */
int err_is_crypto(u64 code);

/* Extract the TLS alert from a CRYPTO_ERROR code (low byte). */
u8 err_alert(u64 code);

#endif
