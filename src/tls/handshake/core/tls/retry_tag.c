#include "tls/handshake/core/tls/retry_tag.h"

#include "common/bytes/util/ct.h"
#include "crypto/symmetric/aead/gcm/gcm.h"

/* RFC 9001 5.8 fixed key and nonce for the v1 Retry Integrity Tag. */
static const u8 RETRY_KEY[16]   = {0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66,
                                   0x57, 0x5a, 0x1d, 0x76, 0x6b, 0x54,
                                   0xe3, 0x68, 0xc8, 0x4e};
static const u8 RETRY_NONCE[12] = {0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63,
                                   0x2b, 0xf2, 0x23, 0x98, 0x25, 0xbb};

/* Build the Retry Pseudo-Packet (ODCID Length, ODCID, Retry) into aad.
 * Returns its length. Caller's aad must hold 1 + odcid_len + retry_len. */
static usz build_pseudo(
    const u8 *odcid, usz odcid_len, const u8 *retry, usz retry_len, u8 *aad) {
  usz n    = 0;
  aad[n++] = (u8)odcid_len;
  for (usz i = 0; i < odcid_len; i++) aad[n++] = odcid[i];
  for (usz i = 0; i < retry_len; i++) aad[n++] = retry[i];
  return n;
}

void quic_retry_tag(
    const u8 *odcid,
    usz       odcid_len,
    const u8 *retry,
    usz       retry_len,
    u8        tag[QUIC_RETRY_TAG]) {
  u8 aad[1 + 20 + 1500]; /* ponytail: MTU-bounded pseudo-packet scratch */
  quic_aes128 a;
  usz         aad_len = build_pseudo(odcid, odcid_len, retry, retry_len, aad);
  quic_aes128_init(&a, RETRY_KEY);
  quic_gcm_ctx g = {&a, RETRY_NONCE, {aad, aad_len}};
  /* empty plaintext: the AEAD tag over the pseudo-packet is the integrity tag
   */
  quic_gcm_seal(&g, quic_span_of(0, 0), tag);
}

int quic_retry_verify(
    const u8 *odcid, usz odcid_len, const u8 *retry_with_tag, usz total_len) {
  u8  want[QUIC_RETRY_TAG];
  usz retry_len = total_len - QUIC_RETRY_TAG;
  quic_retry_tag(odcid, odcid_len, retry_with_tag, retry_len, want);
  return quic_ct_diff16(want, retry_with_tag + retry_len) == 0;
}
