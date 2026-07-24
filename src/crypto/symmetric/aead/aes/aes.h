#ifndef QUIC_AES_AES_H
#define QUIC_AES_AES_H

#include "common/platform/sys/syscall.h"

/* FIPS 197 AES-128. 128-bit block, 128-bit key, 10 rounds. Encryption only
 * (QUIC packet protection and header protection never decrypt with raw AES;
 * GCM uses AES in counter mode and header protection uses AES-ECB encrypt). */

#define QUIC_AES_BLOCK 16
#define QUIC_AES_ROUNDS 10
#define QUIC_AES_RK_WORDS 44 /* 4*(rounds+1) round-key words */

typedef struct {
  u32 rk[QUIC_AES_RK_WORDS];
} quic_aes128;

/* Expand a 16-byte key into the round-key schedule. */
void quic_aes128_init(quic_aes128* a, const u8 key[QUIC_AES_BLOCK]);

/* Encrypt one 16-byte block in place semantics: out = AES(key, in). */
void quic_aes128_encrypt(
    const quic_aes128* a, const u8 in[QUIC_AES_BLOCK], u8 out[QUIC_AES_BLOCK]);

/* FIPS 197 AES-256. 128-bit block, 256-bit key, 14 rounds. */

#define QUIC_AES256_KEY 32
#define QUIC_AES256_ROUNDS 14
#define QUIC_AES256_RK_WORDS 60 /* 4*(rounds+1) round-key words */

typedef struct {
  u32 rk[QUIC_AES256_RK_WORDS];
} quic_aes256;

/* Expand a 32-byte key into the round-key schedule. */
void quic_aes256_init(quic_aes256* a, const u8 key[QUIC_AES256_KEY]);

/* Encrypt one 16-byte block in place semantics: out = AES(key, in). */
void quic_aes256_encrypt(
    const quic_aes256* a, const u8 in[QUIC_AES_BLOCK], u8 out[QUIC_AES_BLOCK]);

#endif
