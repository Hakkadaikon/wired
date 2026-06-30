#include "common/diag/error/codes.h"

/* The enumerated transport error codes occupy 0x00..0x11 (RFC 9000 20.1). */
static int in_enum_range(u64 code) {
  return code <= QUIC_EC_VERSION_NEGOTIATION_ERROR;
}

/* The CRYPTO_ERROR range is 0x0100..0x01ff (RFC 9000 20.1). */
static int in_crypto_range(u64 code) {
  return code >= QUIC_EC_CRYPTO_LO && code <= QUIC_EC_CRYPTO_HI;
}

int quic_error_is_standard(u64 code) {
  return in_enum_range(code) || in_crypto_range(code);
}

int quic_error_is_grease(u64 code) {
  return code % QUIC_EC_GREASE_MOD == QUIC_EC_GREASE_REM;
}

int quic_error_is_app(u64 code) { return !quic_error_is_standard(code); }
