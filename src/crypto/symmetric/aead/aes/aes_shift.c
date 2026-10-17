#include "crypto/symmetric/aead/aes/aes_impl.h"

static void add_round_key(u8 s[16], const u32* rk);
static void sub_bytes(u8 s[16]);
static void shift_col(const u8 s[16], u8 t[16], usz c);
static void shift_rows(u8 s[16]);
static void mix_one(u8* col);
static void mix_columns(u8 s[16]);
static void round_full(u8 s[16], const u32* rk);
static void round_last(u8 s[16], const u32* rk);

/* AddRoundKey: XOR 4 round-key words into the 16-byte state. */
static void add_round_key(u8 s[16], const u32* rk) {
  for (usz c = 0; c < 4; c++) {
    s[4 * c] ^= (u8)(rk[c] >> 24);
    s[4 * c + 1] ^= (u8)(rk[c] >> 16);
    s[4 * c + 2] ^= (u8)(rk[c] >> 8);
    s[4 * c + 3] ^= (u8)rk[c];
  }
}

static void sub_bytes(u8 s[16]) {
  for (usz i = 0; i < 16; i++) s[i] = SBOX[s[i]];
}

/* Fill one shifted column c of the output from state s. */
static void shift_col(const u8 s[16], u8 t[16], usz c) {
  for (usz r = 0; r < 4; r++) t[4 * c + r] = s[4 * ((c + r) % 4) + r];
}

/* ShiftRows on a column-major state (byte r,c at s[4*c+r]). */
static void shift_rows(u8 s[16]) {
  u8 t[16];
  for (usz c = 0; c < 4; c++) shift_col(s, t, c);
  aes128_copy16(s, t);
}

/* MixColumns on one column (4 bytes). */
static void mix_one(u8* col) {
  u8 a0 = col[0], a1 = col[1], a2 = col[2], a3 = col[3];
  col[0] = (u8)(XTIME(a0) ^ (XTIME(a1) ^ a1) ^ a2 ^ a3);
  col[1] = (u8)(a0 ^ XTIME(a1) ^ (XTIME(a2) ^ a2) ^ a3);
  col[2] = (u8)(a0 ^ a1 ^ XTIME(a2) ^ (XTIME(a3) ^ a3));
  col[3] = (u8)((XTIME(a0) ^ a0) ^ a1 ^ a2 ^ XTIME(a3));
}

static void mix_columns(u8 s[16]) {
  for (usz c = 0; c < 4; c++) mix_one(s + 4 * c);
}

/* One full round (rounds 1..9): sub, shift, mix, add. */
static void round_full(u8 s[16], const u32* rk) {
  sub_bytes(s);
  shift_rows(s);
  mix_columns(s);
  add_round_key(s, rk);
}

/* The final round (round 10) omits MixColumns. */
static void round_last(u8 s[16], const u32* rk) {
  sub_bytes(s);
  shift_rows(s);
  add_round_key(s, rk);
}

void aes128_encrypt(
    const aes128* a, const u8 in[AES_BLOCK], u8 out[AES_BLOCK]) {
  u8 s[16];
  aes128_copy16(s, in);
  add_round_key(s, a->rk);
  for (usz r = 1; r < AES_ROUNDS; r++) round_full(s, a->rk + 4 * r);
  round_last(s, a->rk + (usz)4 * AES_ROUNDS);
  aes128_copy16(out, s);
}

void aes256_init(aes256* a, const u8 key[AES256_KEY]) {
  for (usz i = 0; i < 8; i++)
    a->rk[i] = ((u32)key[4 * i] << 24) | ((u32)key[4 * i + 1] << 16) |
               ((u32)key[4 * i + 2] << 8) | key[4 * i + 3];
  for (usz i = 8; i < AES256_RK_WORDS; i++)
    a->rk[i] = a->rk[i - 8] ^ aes128_schedule_word256(a->rk[i - 1], i);
}

void aes256_encrypt(
    const aes256* a, const u8 in[AES_BLOCK], u8 out[AES_BLOCK]) {
  u8 s[16];
  aes128_copy16(s, in);
  add_round_key(s, a->rk);
  for (usz r = 1; r < AES256_ROUNDS; r++) round_full(s, a->rk + 4 * r);
  round_last(s, a->rk + (usz)4 * AES256_ROUNDS);
  aes128_copy16(out, s);
}
