#include "x509/ec_pubkey.h"

/* SEC1 2.3.3. The BIT STRING value is 0x00 (unused bits) then the 65-byte
 * uncompressed point 0x04 || X || Y. */
static int is_uncompressed(const u8 *key, usz key_len)
{
    if (key_len != 66) return 0;
    return key[0] == 0x00 && key[1] == 0x04;
}

static void copy32(u8 dst[32], const u8 *src)
{
    for (usz i = 0; i < 32; i++) dst[i] = src[i];
}

int quic_x509_ec_pubkey(const u8 *spki_key, usz key_len, u8 x[32], u8 y[32])
{
    if (!is_uncompressed(spki_key, key_len)) return 0;
    copy32(x, spki_key + 2);
    copy32(y, spki_key + 34);
    return 1;
}
