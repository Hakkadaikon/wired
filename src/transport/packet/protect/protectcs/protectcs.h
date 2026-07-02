#ifndef QUIC_PROTECTCS_PROTECTCS_H
#define QUIC_PROTECTCS_PROTECTCS_H

#include "common/bytes/span/span.h"

/* RFC 9001 5.3/5.4: cipher-suite-aware packet protection. The AEAD (AES-128-GCM
 * for 0x1301, ChaCha20-Poly1305 for 0x1303) and the header-protection mask are
 * selected by `suite`; this wires the per-suite parts in protect_suite/ into a
 * full seal/open over one packet buffer. The header occupies
 * pkt[0 .. pn_off+pn_len) and the packet number sits at pn_off (pn_len bytes);
 * HP samples 16 bytes at pn_off+4 (RFC 9001 5.4.2). */

/* Suite + key material. key/iv are the AEAD key/iv (key is 16 bytes for AES,
 * 32 for ChaCha; iv is 12), hp_key is the header-protection key. */
typedef struct {
  u16       suite;
  const u8 *key;
  const u8 *iv;
  const u8 *hp_key;
} quic_protectcs_keys;

/* One in-place seal: pkt holds the header followed by payload_len plaintext
 * bytes; the packet number (pn, encoded in pn_len bytes) sits at pn_off. */
typedef struct {
  u8 *pkt;
  usz pn_off;
  u8  pn_len;
  u64 pn;
  usz payload_len;
} quic_protectcs_seal_io;

/* Seal in place: encrypts the payload (AEAD over the header as AAD), appends
 * the 16-byte tag, then applies header protection. Writes the total protected
 * length to *out_len and returns 1, or 0 on an unknown suite. */
int quic_protectcs_seal(
    const quic_protectcs_keys    *k,
    const quic_protectcs_seal_io *io,
    usz                          *out_len);

/* One in-place open: pkt holds a protected packet with the packet number at
 * pn_off. */
typedef struct {
  quic_mspan pkt;
  usz        pn_off;
} quic_protectcs_open_io;

/* Open in place: removes header protection (recovering pn_len from byte0),
 * verifies and decrypts the payload, and points *payload at the plaintext
 * within pkt. Returns 1 on success, 0 on an unknown suite or authentication
 * failure. */
int quic_protectcs_open(
    const quic_protectcs_keys    *k,
    const quic_protectcs_open_io *io,
    quic_span                    *payload);

#endif
