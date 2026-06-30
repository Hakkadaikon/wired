#ifndef QUIC_PROTECT_PROTECT_H
#define QUIC_PROTECT_PROTECT_H

#include "crypto/symmetric/aead/aes/aes.h"
#include "tls/handshake/core/tls/initial.h"

/* RFC 9001 5.3/5.4 packet protection pipeline for AES-128-GCM Initial
 * packets: build the AEAD nonce from iv XOR packet number, seal the payload
 * with the header as AAD, then apply header protection over the sample. */

/* Compute the 12-byte AEAD nonce: iv with the packet number XORed into its
 * low bytes (RFC 9001 5.3). */
void quic_protect_nonce(const u8 iv[QUIC_INITIAL_IV], u64 pn,
                        u8 nonce[QUIC_INITIAL_IV]);

/* Protect one Initial packet.
 *   hdr/hdr_len : unprotected header bytes, ending with the packet number;
 *                 pn_off is the offset of the packet number within hdr.
 *   pn_len      : encoded packet-number length (1..4).
 *   pn          : full packet number (for the nonce).
 *   payload     : plaintext frames.
 * Writes header + ciphertext + tag into out (cap bytes), applies header
 * protection in place, and returns the total protected length, or 0.
 * keys.key/iv are the AEAD key/iv; keys.hp is the header-protection key. */
usz quic_protect_seal(const quic_initial_keys *keys, const quic_aes128 *hp_aes,
                      const u8 *hdr, usz hdr_len, usz pn_off, usz pn_len, u64 pn,
                      const u8 *payload, usz payload_len, u8 *out, usz cap);

/* Reverse of quic_protect_seal on a protected packet held in pkt (pkt_len
 * bytes), with the header occupying hdr_len bytes and the packet number at
 * pn_off (pn_len bytes). Removes header protection in place, then verifies
 * and decrypts the payload into pkt's payload region. `pn` is the full
 * packet number (recovered by the caller). Returns the plaintext length, or
 * 0 if authentication fails. */
usz quic_protect_open(const quic_initial_keys *keys, const quic_aes128 *hp_aes,
                      u8 *pkt, usz pkt_len, usz hdr_len, usz pn_off, usz pn_len,
                      u64 pn);

#endif

