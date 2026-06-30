#include "protect_suite/hp_suite.h"
#include "tls/handshake/core/tls/cipher.h"
#include "hp/hp.h"
#include "hp/hp_chacha.h"

int quic_hp_suite_mask(u16 suite, const u8 *hp_key, const u8 sample[16],
                       u8 mask[5])
{
    if (suite == QUIC_TLS_AES_128_GCM_SHA256) {
        quic_aes128 hp;
        quic_aes128_init(&hp, hp_key);
        quic_hp_mask(&hp, sample, mask);
        return 1;
    }
    if (suite == QUIC_TLS_CHACHA20_POLY1305_SHA256) {
        quic_hp_chacha_mask(hp_key, sample, mask);
        return 1;
    }
    return 0;
}
