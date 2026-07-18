#ifndef QUIC_TLS_APPKEYS_H
#define QUIC_TLS_APPKEYS_H

#include "common/bytes/span/span.h"
#include "crypto/kdf/hkdf/hkdf.h"
#include "tls/handshake/core/tls/initial.h"

/* quic_tls_app_keys inputs: master is the Master Secret, transcript the
 * handshake bytes hashed for the traffic secret, is_server selects the
 * "s ap traffic"/"c ap traffic" label. */
typedef struct {
  const u8* master; /* QUIC_HKDF_PRK bytes */
  quic_span transcript;
  int       is_server;
} quic_app_keys_in;

/* RFC 9001 4.1 / RFC 8446 7.1: 1-RTT (application) packet protection keys.
 * From the Master Secret, derive client/server application_traffic_secret_0
 * = Derive-Secret(Master, "c ap traffic"/"s ap traffic", transcript), then
 * expand the QUIC key/iv/hp for the requested (is_server) direction
 * (AES_128_GCM_SHA256; equivalent to quic_tls_app_keys_suite with suite =
 * QUIC_TLS_AES_128_GCM_SHA256). */
void quic_tls_app_keys(const quic_app_keys_in* in, quic_initial_keys* out);

/* Same as quic_tls_app_keys, but sizes the derived key/hp for the given
 * negotiated TLS 1.3 cipher suite (RFC 8446 B.4; AES_128_GCM_SHA256 key=16/
 * hp=16, CHACHA20_POLY1305_SHA256 key=32/hp=32 -- RFC 9001 5.1/5.4.3). */
void quic_tls_app_keys_suite(
    const quic_app_keys_in* in, u16 suite, quic_initial_keys* out);

#endif
