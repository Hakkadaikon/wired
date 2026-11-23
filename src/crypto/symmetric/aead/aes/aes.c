#include "crypto/symmetric/aead/aes/aes_impl.h"

static u32 sub_word(u32 w);
static u32 schedule_word(u32 prev, usz i);

/* 10 entries cover both AES-128 (uses RCON[0..9], i/4-1 up to 9) and
 * AES-256 (uses RCON[0..6], i/8-1 up to 6). */
static const u8 RCON[10] = {0x01, 0x02, 0x04, 0x08, 0x10,
                            0x20, 0x40, 0x80, 0x1b, 0x36};

/* SubWord (FIPS 197 5.2) with no key-indexed table: the hardware AES round
 * where the CPU has AES instructions (x86 AES-NI aesenclast / ARMv8 AESE),
 * the arithmetic S-box otherwise. */
static u32 sub_word(u32 w) {
  if (gcmx86_supported()) {
    return gcmx86_subword(w);
  }
  return (u32)aes128_sbox8(w);
}

/* The per-word key-schedule core: rotate+sub+rcon on multiples of 4. */
static u32 schedule_word(u32 prev, usz i) {
  if (i % 4 != 0) {
    return prev;
  }
  return sub_word((prev << 8) | (prev >> 24)) ^ ((u32)RCON[i / 4 - 1] << 24);
}

/* FIPS 197 5.2 Figure 11: Nk=8 (AES-256) key-schedule core. Every 8th word
 * gets RotWord+SubWord+Rcon (as in AES-128's every-4th-word rule); Nk>6
 * additionally applies SubWord alone at the halfway word (i%Nk==4), which
 * AES-128/192 do not have. */
u32 aes128_schedule_word256(u32 prev, usz i) {
  if (i % 8 == 0) {
    return sub_word((prev << 8) | (prev >> 24)) ^ ((u32)RCON[i / 8 - 1] << 24);
  }
  if (i % 8 == 4) {
    return sub_word(prev);
  }
  return prev;
}

void aes128_init(aes128* a, const u8 key[AES_BLOCK]) {
  for (usz i = 0; i < 4; i++) {
    a->rk[i] = ((u32)key[4 * i] << 24) | ((u32)key[4 * i + 1] << 16) |
               ((u32)key[4 * i + 2] << 8) | key[4 * i + 3];
  }
  for (usz i = 4; i < AES_RK_WORDS; i++) {
    a->rk[i] = a->rk[i - 4] ^ schedule_word(a->rk[i - 1], i);
  }
}
