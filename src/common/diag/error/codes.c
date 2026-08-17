#include "common/diag/error/codes.h"

/* The enumerated transport error codes occupy 0x00..0x11 (RFC 9000 20.1). */
static int in_enum_range(u64 code) {
  return code <= EC_VERSION_NEGOTIATION_ERROR;
}

/* The CRYPTO_ERROR range is 0x0100..0x01ff (RFC 9000 20.1). */
static int in_crypto_range(u64 code) {
  return code >= EC_CRYPTO_LO && code <= EC_CRYPTO_HI;
}

int error_is_standard(u64 code) {
  return in_enum_range(code) || in_crypto_range(code);
}

int error_is_grease(u64 code) { return code % EC_GREASE_MOD == EC_GREASE_REM; }

int error_is_app(u64 code) { return !error_is_standard(code); }
