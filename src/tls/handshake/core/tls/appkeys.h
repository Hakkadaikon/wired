#ifndef TLS_APPKEYS_H
#define TLS_APPKEYS_H

#include "common/bytes/span/span.h"
#include "crypto/kdf/hkdf/hkdf.h"
#include "tls/handshake/core/tls/initial.h"

/** tls_app_keys inputs: master is the Master Secret, transcript the
 * handshake bytes hashed for the traffic secret, is_server selects the
 * "s ap traffic"/"c ap traffic" label. version picks the QUIC label prefix
 * for the packet-protection expand ("quic " for v1, "quicv2 " for v2,
 * RFC 9369 3.3.1); 0 (every pre-existing initializer) means v1. */
typedef struct {
  const u8*  master; /* HKDF_PRK bytes */
  wired_span transcript;
  int        is_server;
  u32        version;
} app_keys_in;

/* RFC 9001 4.1 / RFC 8446 7.1: 1-RTT (application) packet protection keys.
 * From the Master Secret, derive client/server application_traffic_secret_0
 * = Derive-Secret(Master, "c ap traffic"/"s ap traffic", transcript), then
 * expand the QUIC key/iv/hp for the requested (is_server) direction
 * (AES_128_GCM_SHA256; equivalent to tls_app_keys_suite with suite =
 * TLS_AES_128_GCM_SHA256). */
void tls_app_keys(const app_keys_in* in, initial_keys* out);

/* Same as tls_app_keys, but sizes the derived key/hp for the given
 * negotiated TLS 1.3 cipher suite (RFC 8446 B.4; AES_128_GCM_SHA256 key=16/
 * hp=16, CHACHA20_POLY1305_SHA256 key=32/hp=32 -- RFC 9001 5.1/5.4.3). */
void tls_app_keys_suite(const app_keys_in* in, u16 suite, initial_keys* out);

#endif
