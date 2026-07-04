#ifndef QUIC_PROTECT_PROTECT_H
#define QUIC_PROTECT_PROTECT_H

#include "common/bytes/span/span.h"
#include "crypto/symmetric/aead/aes/aes.h"
#include "tls/handshake/core/tls/initial.h"

/* RFC 9001 5.3/5.4 packet protection pipeline for AES-128-GCM Initial
 * packets: build the AEAD nonce from iv XOR packet number, seal the payload
 * with the header as AAD, then apply header protection over the sample. */

/* AEAD keys plus the expanded header-protection cipher for one packet-number
 * space. keys.key/iv are the AEAD key/iv; hp is expanded from keys.hp. */
typedef struct {
  const quic_initial_keys* keys;
  const quic_aes128*       hp;
} quic_protect_keys;

/* Compute the 12-byte AEAD nonce: iv with the packet number XORed into its
 * low bytes (RFC 9001 5.3). */
void quic_protect_nonce(
    const u8 iv[QUIC_INITIAL_IV], u64 pn, u8 nonce[QUIC_INITIAL_IV]);

/* One Initial packet to protect. hdr is the unprotected header ending with
 * the packet number; pn_off is the packet number's offset within hdr and
 * pn_len its encoded length (1..4). pn is the full packet number (for the
 * nonce), payload the plaintext frames, out the destination buffer. */
typedef struct {
  quic_span  hdr;
  usz        pn_off;
  usz        pn_len;
  u64        pn;
  quic_span  payload;
  quic_mspan out;
} quic_protect_seal_io;

/* Write header + ciphertext + tag into io->out, apply header protection in
 * place, and return the total protected length, or 0 if it does not fit. */
usz quic_protect_seal(
    const quic_protect_keys* k, const quic_protect_seal_io* io);

/* Reverse of quic_protect_seal on a protected packet held in pkt (modified
 * in place), with the header occupying hdr_len bytes and the packet number
 * at pn_off (pn_len bytes). pn is the full packet number (recovered by the
 * caller). */
typedef struct {
  quic_mspan pkt;
  usz        hdr_len;
  usz        pn_off;
  usz        pn_len;
  u64        pn;
} quic_protect_open_io;

/* Removes header protection in place, then verifies and decrypts the payload
 * into pkt's payload region. Returns the plaintext length, or 0 if
 * authentication fails. */
usz quic_protect_open(
    const quic_protect_keys* k, const quic_protect_open_io* io);

#endif
