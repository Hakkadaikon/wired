#ifndef QUIC_TLS_APPKEYS_H
#define QUIC_TLS_APPKEYS_H

#include "crypto/kdf/hkdf/hkdf.h"
#include "tls/handshake/core/tls/initial.h"

/* RFC 9001 4.1 / RFC 8446 7.1: 1-RTT (application) packet protection keys.
 * From the Master Secret, derive client/server application_traffic_secret_0
 * = Derive-Secret(Master, "c ap traffic"/"s ap traffic", transcript), then
 * expand the QUIC key/iv/hp for the requested (is_server) direction. */
void quic_tls_app_keys(const u8 master[QUIC_HKDF_PRK],
                       const u8 *transcript, usz tlen,
                       int is_server, quic_initial_keys *out);

#endif
