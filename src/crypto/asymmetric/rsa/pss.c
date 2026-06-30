#include "crypto/asymmetric/rsa/pss.h"

#include "crypto/asymmetric/rsa/mgf1.h"
#include "crypto/symmetric/hash/hash/sha256.h"

#define PSS_SALT_LEN 32
#define PSS_MAX_EM 512

/* Count of leftmost bits in the top octet that RFC 8017 9.1.2 requires zero. */
static usz pss_top_zero_bits(usz em_len, usz em_bits) {
  return 8 * em_len - em_bits;
}

/* maskedDB length = em_len - hLen - 1. */
static usz pss_db_len(usz em_len, usz hash_len) {
  return em_len - hash_len - 1;
}

/* RFC 8017 9.1.2 step 6: leftmost bits of maskedDB must be zero. */
static int pss_top_bits_clear(u8 top, usz zero_bits) {
  return (top & (0xff << (8 - zero_bits))) == 0;
}

/* DB = maskedDB XOR dbMask, then clear the leftmost zero_bits (step 8-9). */
static void pss_unmask_db(u8 *db, usz db_len, const u8 *h, usz zero_bits) {
  u8 mask[PSS_MAX_EM];
  quic_mgf1_sha256(h, 32, mask, db_len);
  for (usz i = 0; i < db_len; i++) db[i] ^= mask[i];
  db[0] &= (u8)(0xff >> zero_bits);
}

/* RFC 8017 9.1.2 step 10: PS (zeros) then 0x01 before the salt. */
static int pss_padding_ok(const u8 *db, usz db_len, usz salt_len) {
  usz one = db_len - salt_len - 1;
  for (usz i = 0; i < one; i++)
    if (db[i] != 0x00) return 0;
  return db[one] == 0x01;
}

/* H' = SHA-256(0x00*8 || mHash || salt); compare to H (step 12-14). */
static int pss_hprime_eq(
    const u8 *mhash, const u8 *salt, usz salt_len, const u8 *h) {
  u8              zeros[8] = {0};
  u8              hp[32];
  quic_sha256_ctx s;
  quic_sha256_init(&s);
  quic_sha256_update(&s, zeros, 8);
  quic_sha256_update(&s, mhash, 32);
  quic_sha256_update(&s, salt, salt_len);
  quic_sha256_final(&s, hp);
  u8 d = 0;
  for (usz i = 0; i < 32; i++) d |= hp[i] ^ h[i];
  return d == 0;
}

/* Reject inputs that cannot form a valid SHA-256/saltLen-32 PSS encoding. */
static int pss_sizes_bad(usz em_len, usz hash_len) {
  if (hash_len != 32 || em_len > PSS_MAX_EM) return 1;
  return em_len < hash_len + PSS_SALT_LEN + 2; /* RFC 8017 9.1.2 step 3 */
}

/* RFC 8017 9.1.2 step 5: split maskedDB and H, unmask DB. */
static void pss_recover_db(
    const u8 *em, usz db_len, u8 *db, const u8 **h, usz zero_bits) {
  for (usz i = 0; i < db_len; i++) db[i] = em[i];
  *h = em + db_len;
  pss_unmask_db(db, db_len, *h, zero_bits);
}

/* RFC 8017 9.1.2 steps 3-6: trailer 0xbc and the cleared top bits of EM. */
static int pss_prefix_bad(const u8 *em, usz em_len, usz hash_len, usz em_bits) {
  if (pss_sizes_bad(em_len, hash_len)) return 1;
  if (em[em_len - 1] != 0xbc) return 1;
  return !pss_top_bits_clear(em[0], pss_top_zero_bits(em_len, em_bits));
}

/* DB recovered and padding/hash-checked (steps 8-14). 1 if salt is consistent.
 */
static int pss_db_consistent(
    const u8 *em, usz db_len, usz zero_bits, const u8 *mhash) {
  u8        db[PSS_MAX_EM];
  const u8 *h;
  pss_recover_db(em, db_len, db, &h, zero_bits);
  if (!pss_padding_ok(db, db_len, PSS_SALT_LEN)) return 0;
  return pss_hprime_eq(mhash, db + db_len - PSS_SALT_LEN, PSS_SALT_LEN, h);
}

int quic_emsa_pss_verify(
    const u8 *em, usz em_len, usz em_bits, const u8 *mhash, usz hash_len) {
  if (pss_prefix_bad(em, em_len, hash_len, em_bits)) return 0;
  usz db_len    = pss_db_len(em_len, hash_len);
  usz zero_bits = pss_top_zero_bits(em_len, em_bits);
  return pss_db_consistent(em, db_len, zero_bits, mhash);
}
