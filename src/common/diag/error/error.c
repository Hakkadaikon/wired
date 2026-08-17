#include "common/diag/error/error.h"

u64 err_crypto(u8 tls_alert) { return QUIC_ERR_CRYPTO_BASE + (u64)tls_alert; }

int err_is_crypto(u64 code) {
  return code >= QUIC_ERR_CRYPTO_BASE && code <= QUIC_ERR_CRYPTO_BASE + 0xff;
}

u8 err_alert(u64 code) { return (u8)(code & 0xff); }
