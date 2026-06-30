#include "tls/handshake/core/tls/retry_tag_v2.h"

/* RFC 9369 3.3.3 */
static const u8 RETRY_KEY_V2[16]   = {0x8f, 0xb4, 0xb0, 0x1b, 0x56, 0xac,
                                      0x48, 0xe2, 0x60, 0xfb, 0xcb, 0xce,
                                      0xad, 0x7c, 0xcc, 0x92};
static const u8 RETRY_NONCE_V2[12] = {0xd8, 0x69, 0x69, 0xbc, 0x2d, 0x7c,
                                      0x6d, 0x99, 0x90, 0xef, 0xb0, 0x4a};

void quic_retry_tag_v2_key(const u8 **key, usz *len) {
  *key = RETRY_KEY_V2;
  *len = sizeof RETRY_KEY_V2;
}

void quic_retry_tag_v2_nonce(const u8 **nonce, usz *len) {
  *nonce = RETRY_NONCE_V2;
  *len   = sizeof RETRY_NONCE_V2;
}
