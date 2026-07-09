#ifndef QUIC_P256CERT_P256CERT_H
#define QUIC_P256CERT_P256CERT_H

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"

/* An ECDSA P-256 signing key: the private scalar and its affine public key,
 * each 32 bytes, caller-owned. san_ipv4, if non-0, is a 4-byte IPv4 address
 * (network byte order) added to the certificate's Subject Alternative Name
 * alongside the fixed dNSName=localhost entry (RFC 5280 4.2.1.6 iPAddress) --
 * a browser validating a WebTransport connection to an IP literal (e.g.
 * serverCertificateHashes pinning to a bare IP, no DNS name) checks the SAN
 * for that literal, not just the pinned hash; without it, hostname
 * validation fails even though the pinned hash matches. 0 to omit (the SAN
 * carries only dNSName=localhost, the pre-existing behavior). now_secs, if
 * non-0, is a UNIX epoch second the validity window is anchored to:
 * notBefore = now_secs, notAfter = now_secs + 14 days (the W3C WebTransport
 * spec's serverCertificateHashes pinning rejects any cert whose validity
 * window exceeds 14 days -- see
 * https://www.w3.org/TR/webtransport/#dom-webtransporthash). 0 to keep the
 * pre-existing fixed 2020-2030 window (tests only; a real server must pass
 * quic_clock_epoch_secs()). */
typedef struct {
  const u8* priv;
  const u8* x;
  const u8* y;
  const u8* san_ipv4; /**< 4 bytes, network byte order, or 0 to omit */
  u64       now_secs; /**< UNIX epoch seconds, or 0 for the fixed window */
} quic_p256cert_key;

/* RFC 5280 4.1 / SEC1. Build a self-signed ECDSA P-256 X.509 certificate
 * (self-issued CN=localhost, fixed validity, secp256r1 SPKI,
 * ecdsa-with-SHA256 signature) from the key into out, setting out->len.
 * Returns 1 ok, 0 on failure. */
int quic_p256cert_build(const quic_p256cert_key* k, quic_obuf* out);

#endif
