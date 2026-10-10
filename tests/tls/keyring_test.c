#include "tls/keys/keyring/keyring.h"

#include "common/bytes/util/ct.h"
#include "test.h"

/* HMAC-SHA256(0xa1 x 32, be64(e)), computed with Python hmac/hashlib. */
static const u8 keyring_want_e1[KEYRING_KEY] = {
    0xf8, 0xfe, 0xd5, 0x13, 0xa1, 0xda, 0xcf, 0x08, 0xf4, 0x33, 0xae,
    0x47, 0xfd, 0xb8, 0x0b, 0x58, 0x2c, 0x23, 0x32, 0x1a, 0x56, 0xe8,
    0xa0, 0xca, 0xb5, 0x13, 0x7a, 0x60, 0xba, 0xaa, 0xf0, 0x0e};
static const u8 keyring_want_e2[KEYRING_KEY] = {
    0xf3, 0x59, 0xe4, 0x26, 0xab, 0x3b, 0xfd, 0x17, 0x18, 0x34, 0x85,
    0x1d, 0x92, 0x83, 0xd5, 0x60, 0xf4, 0x26, 0x6e, 0x77, 0x6c, 0xbd,
    0xc9, 0xa2, 0x0f, 0x45, 0xa5, 0xaa, 0xf5, 0x3a, 0x0a, 0x0d};

static int keyring_is(
    const u8 seed[KEYRING_KEY], u64 now, u64 back, const u8* want) {
  u8 got[KEYRING_KEY];
  keyring_key(seed, now, back, got);
  return ct_diff32(got, want) == 0;
}

/* Epoch boundaries: the last second of epoch 1 still yields epoch 1's key;
 * the first second of epoch 2 rotates, with epoch 1's key as previous. */
static void test_keyring_epoch_boundary(void) {
  u8  seed[KEYRING_KEY];
  u64 p = KEYRING_PERIOD_SECS;
  bytes_memset(seed, 0xa1, sizeof seed);
  CHECK(keyring_is(seed, 2 * p - 1, 0, keyring_want_e1));
  CHECK(keyring_is(seed, 2 * p, 0, keyring_want_e2));
  CHECK(keyring_is(seed, 2 * p, 1, keyring_want_e1));
  CHECK(keyring_is(seed, 3 * p - 1, 1, keyring_want_e1));
  CHECK(!keyring_is(seed, 3 * p, 1, keyring_want_e1)); /* two epochs: gone */
}

void test_keyring(void) { test_keyring_epoch_boundary(); }
