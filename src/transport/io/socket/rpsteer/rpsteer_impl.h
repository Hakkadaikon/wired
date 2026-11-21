#ifndef RPSTEER_RPSTEER_IMPL_H
#define RPSTEER_RPSTEER_IMPL_H

#include "transport/io/socket/rpsteer/rpsteer.h"

/* Classic BPF opcodes (linux/filter.h encodings): class LD 0x00 / LDX 0x01 /
 * ST 0x02 / ALU 0x04 / JMP 0x05 / RET 0x06, size B 0x10 / W 0x00, mode ABS
 * 0x20 / IND 0x40 / MEM 0x60 / LEN 0x80 / IMM 0x00, ALU op in the high
 * nibble, src K 0x00 / X 0x08. Validated against the running kernel by the
 * attach-and-send test in tests/transport/rpsteer_test.c. */
#define RPSTEER_LD_LEN 0x80  /* A = wire length */
#define RPSTEER_LDB_ABS 0x30 /* A = pkt[k] */
#define RPSTEER_LDB_IND 0x50 /* A = pkt[X + k] */
#define RPSTEER_LDX_IMM 0x01 /* X = k */
#define RPSTEER_LD_MEM 0x60  /* A = M[k] */
#define RPSTEER_LDX_MEM 0x61 /* X = M[k] */
#define RPSTEER_ST_MEM 0x02  /* M[k] = A */
#define RPSTEER_ADD_X 0x0c   /* A += X */
#define RPSTEER_ADD_K 0x04   /* A += k */
#define RPSTEER_MUL_K 0x24   /* A *= k (32-bit) */
#define RPSTEER_AND_K 0x54   /* A &= k */
#define RPSTEER_OR_X 0x4c    /* A |= X */
#define RPSTEER_LSH_K 0x64   /* A <<= k */
#define RPSTEER_RSH_K 0x74   /* A >>= k */
#define RPSTEER_XOR_K 0xa4   /* A ^= k */
#define RPSTEER_XOR_X 0xac   /* A ^= X */
#define RPSTEER_JA 0x05      /* pc += k */
#define RPSTEER_JGE_K 0x35   /* pc += A >= k ? jt : jf */
#define RPSTEER_JSET_K 0x45  /* pc += A & k ? jt : jf */
#define RPSTEER_RET_A 0x16   /* return A */
#define RPSTEER_RET_K 0x06   /* return k */

/* Scratch slots (M[0..15]): 0 dcid[0], 1 a / y_lo, 2 a0, 3 a1, 4..7 the
 * four 16x16 partial products, 8 running sum, 9 x_hi. */

/** One fixed instruction of an emission table (jt/jf always 0; the few
 * jump/keyed instructions are patched over the table's placeholder). */
typedef struct {
  u16 code;
  u32 k;
} rpsteer_op;

/* Emit ops[0..n) at o[i..i+n) (rpsteer_mix.c). */
void rpsteer_emit_ops(u64* o, u32 i, const rpsteer_op* ops, u32 n);

/* 44 instructions at index i (rpsteer_mix.c): A = the high 32 bits of
 * M[1] * b (b a build-time constant), from four 16x16 partial products --
 * cBPF's MUL keeps only the low 32 bits, so the 64-bit products
 * ncid_route_mask needs are rebuilt limb by limb. Enters with A == M[1]. */
void rpsteer_emit_mulhi(u64* o, u32 i, u32 b);

#endif
