#ifndef AES_AES_H
#define AES_AES_H

#include "common/platform/sys/syscall.h"

/* FIPS 197 AES-128. 128-bit block, 128-bit key, 10 rounds. Encryption only
 * (QUIC packet protection and header protection never decrypt with raw AES;
 * GCM uses AES in counter mode and header protection uses AES-ECB encrypt). */

#define AES_BLOCK 16
#define AES_ROUNDS 10
#define AES_RK_WORDS 44 /* 4*(rounds+1) round-key words */

/** Expanded AES-128 round-key schedule. */
typedef struct {
  u32 rk[AES_RK_WORDS];
} aes128;

/* Expand a 16-byte key into the round-key schedule. */
void aes128_init(aes128* a, const u8 key[AES_BLOCK]);

/* Encrypt one 16-byte block in place semantics: out = AES(key, in). */
void aes128_encrypt(const aes128* a, const u8 in[AES_BLOCK], u8 out[AES_BLOCK]);

/* FIPS 197 AES-256. 128-bit block, 256-bit key, 14 rounds. */

#define AES256_KEY 32
#define AES256_ROUNDS 14
#define AES256_RK_WORDS 60 /* 4*(rounds+1) round-key words */

/** Expanded AES-256 round-key schedule. */
typedef struct {
  u32 rk[AES256_RK_WORDS];
} aes256;

/* Expand a 32-byte key into the round-key schedule. */
void aes256_init(aes256* a, const u8 key[AES256_KEY]);

/* Encrypt one 16-byte block in place semantics: out = AES(key, in). */
void aes256_encrypt(const aes256* a, const u8 in[AES_BLOCK], u8 out[AES_BLOCK]);

#endif
