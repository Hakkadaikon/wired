#ifndef QUIC_WT_EXPORTER_EXPORTER_H
#define QUIC_WT_EXPORTER_EXPORTER_H

#include "common/bytes/span/span.h"
#include "crypto/kdf/hkdf/hkdf.h"

/* draft-ietf-webtrans-http3-15 4.8: Use of Keying Material Exporters.
 * WebTransport derives per-session TLS exporters (RFC 8446 7.5) so that
 * sessions sharing one QUIC connection get independent keying material.
 * The TLS-Exporter label is fixed to "EXPORTER-WebTransport"; the context
 * is the serialized "WebTransport Exporter Context" struct:
 *
 *   WebTransport Exporter Context {
 *     WebTransport Session ID (64),
 *     WebTransport Application-Supplied Exporter Label Length (8),
 *     WebTransport Application-Supplied Exporter Label (8..),
 *     WebTransport Application-Supplied Exporter Context Length (8),
 *     WebTransport Application-Supplied Exporter Context (..)
 *   }
 *
 * (session ID big-endian per RFC 9000 1.3's fixed-width integer encoding;
 * the two length-prefixed fields are limited to 255 bytes each by their
 * 8-bit length fields).
 */

#define QUIC_WT_EXPORTER_CTX_LABEL_MAX 255
#define QUIC_WT_EXPORTER_CTX_CONTEXT_MAX 255
/* 8 (session id) + 1 + label + 1 + context, at the two max lengths. */
#define QUIC_WT_EXPORTER_CTX_MAX                \
  (8 + 1 + QUIC_WT_EXPORTER_CTX_LABEL_MAX + 1 + \
   QUIC_WT_EXPORTER_CTX_CONTEXT_MAX)

/* Serialize the WebTransport Exporter Context struct into out (capacity
 * QUIC_WT_EXPORTER_CTX_MAX or more). Returns the serialized length, or 0 if
 * label or app_context exceeds its 255-byte field, or out lacks capacity.
 * @param session_id  the WebTransport session's identity (its CONNECT
 *   stream ID, session.h's wired_wt_session.connect_stream_id)
 * @param label       the application-supplied exporter label
 * @param app_context the application-supplied exporter context (may be
 *   empty, wired_span_of(0, 0))
 * @param out         receives the serialized bytes
 * @param cap         capacity of out
 */
usz quic_wt_exporter_ctx_encode(
    u64 session_id, wired_span label, wired_span app_context, u8* out, usz cap);

/* draft-ietf-webtrans-http3-15 4.8: compute
 *   TLS-Exporter("EXPORTER-WebTransport", WebTransport Exporter Context,
 *                 okm.n)
 * (RFC 8446 7.5) for the given session, application label, and
 * application context. exporter_secret is the connection's
 * exporter_master_secret (tls/keys/schedule_drive/keyschedule.h's
 * quic_keysched_exporter_secret).
 * @return 1 on success, 0 if label/app_context exceed 255 bytes or okm's
 *   length does not fit hkdf_expand_label */
int quic_wt_exporter(
    const u8    exporter_secret[QUIC_HKDF_PRK],
    u64         session_id,
    wired_span  label,
    wired_span  app_context,
    wired_mspan okm);

#endif
