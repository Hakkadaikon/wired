#include "transport/io/socket/rpsteer/rpsteer_impl.h"

/* The fallback return's instruction index (kernel hash selection). */
#define RPSTEER_IDX_FB (RPSTEER_PROG_LEN - 1)

u64 rpsteer_insn(u16 code, u8 jt, u8 jf, u32 k) {
  return (u64)code | ((u64)jt << 16) | ((u64)jf << 24) | ((u64)k << 32);
}

/* idx 0-8: length guards (a too-short datagram cannot carry
 * NCID_ROUTE_MIN_LEN DCID bytes -> fallback, never an aborted load, whose
 * cBPF return of 0 would select member 0), the Header Form split (RFC 9000
 * 17.2/17.3), and X = the DCID's offset (short 1, long 6). */
static void rpsteer_emit_head(u64* o) {
  o[0] = rpsteer_insn(RPSTEER_LD_LEN, 0, 0, 0);
  o[1] = rpsteer_insn(RPSTEER_JGE_K, 0, (u8)(RPSTEER_IDX_FB - 2), 1 + 5);
  o[2] = rpsteer_insn(RPSTEER_LDB_ABS, 0, 0, 0);
  o[3] = rpsteer_insn(RPSTEER_JSET_K, 2, 0, 0x80);
  o[4] = rpsteer_insn(RPSTEER_LDX_IMM, 0, 0, 1);
  o[5] = rpsteer_insn(RPSTEER_JA, 0, 0, 3);
  o[6] = rpsteer_insn(RPSTEER_LD_LEN, 0, 0, 0);
  o[7] = rpsteer_insn(RPSTEER_JGE_K, 0, (u8)(RPSTEER_IDX_FB - 8), 6 + 5);
  o[8] = rpsteer_insn(RPSTEER_LDX_IMM, 0, 0, 6);
}

/* idx 9-17: dcid[0..3] -> M0..M3, dcid[4] left in A. */
static void rpsteer_emit_cid_load(u64* o) {
  for (u32 j = 0; j < 4; j++) {
    o[9 + 2 * j]  = rpsteer_insn(RPSTEER_LDB_IND, 0, 0, j);
    o[10 + 2 * j] = rpsteer_insn(RPSTEER_ST_MEM, 0, 0, j);
  }
  o[17] = rpsteer_insn(RPSTEER_LDB_IND, 0, 0, 4);
}

/* idx 18-28: A = w = LE32(dcid[1..4]) (ncid_route_mask's load), then
 * a = w ^ k0lo -> M1 and A. */
static void rpsteer_emit_w(u64* o, u32 k0lo) {
  static const u32 m[3] = {3, 2, 1};
  for (u32 j = 0; j < 3; j++) {
    o[18 + 3 * j] = rpsteer_insn(RPSTEER_LSH_K, 0, 0, 8);
    o[19 + 3 * j] = rpsteer_insn(RPSTEER_LDX_MEM, 0, 0, m[j]);
    o[20 + 3 * j] = rpsteer_insn(RPSTEER_OR_X, 0, 0, 0);
  }
  o[27] = rpsteer_insn(RPSTEER_XOR_K, 0, 0, k0lo);
  o[28] = rpsteer_insn(RPSTEER_ST_MEM, 0, 0, 1);
}

/* idx 73-84: x = (w ^ k0) * k1 in halves -- x_hi = mulhi(a,k1lo) + a*k1hi
 * + k0hi*k1lo (the last folded into the constant c1) -> M9, then
 * y_lo = x_lo ^ x_hi (ncid_route_mask's x ^= x >> 32) -> M1 and A. */
static void rpsteer_emit_round1_tail(u64* o, u32 k1lo, u32 k1hi, u32 c1) {
  o[73] = rpsteer_insn(RPSTEER_ST_MEM, 0, 0, 8);
  o[74] = rpsteer_insn(RPSTEER_LD_MEM, 0, 0, 1);
  o[75] = rpsteer_insn(RPSTEER_MUL_K, 0, 0, k1hi);
  o[76] = rpsteer_insn(RPSTEER_LDX_MEM, 0, 0, 8);
  o[77] = rpsteer_insn(RPSTEER_ADD_X, 0, 0, 0);
  o[78] = rpsteer_insn(RPSTEER_ADD_K, 0, 0, c1);
  o[79] = rpsteer_insn(RPSTEER_ST_MEM, 0, 0, 9);
  o[80] = rpsteer_insn(RPSTEER_LD_MEM, 0, 0, 1);
  o[81] = rpsteer_insn(RPSTEER_MUL_K, 0, 0, k1lo);
  o[82] = rpsteer_insn(RPSTEER_LDX_MEM, 0, 0, 9);
  o[83] = rpsteer_insn(RPSTEER_XOR_X, 0, 0, 0);
  o[84] = rpsteer_insn(RPSTEER_ST_MEM, 0, 0, 1);
}

/* idx 129-144: z_hi = the high half of y * k2 (mask = z_hi >> 24, i.e. the
 * 64-bit x >> 56), core = dcid[0] ^ mask, then return core when < nsock
 * else the fallback 0xffffffff. The three keyed/jump slots (131, 136, 142)
 * hold placeholders here and are patched below. */
static const rpsteer_op rpsteer_round2[16] = {
    {RPSTEER_ST_MEM, 8},         {RPSTEER_LD_MEM, 1}, {RPSTEER_MUL_K, 0},
    {RPSTEER_LDX_MEM, 8},        {RPSTEER_ADD_X, 0},  {RPSTEER_ST_MEM, 8},
    {RPSTEER_LD_MEM, 9},         {RPSTEER_MUL_K, 0},  {RPSTEER_LDX_MEM, 8},
    {RPSTEER_ADD_X, 0},          {RPSTEER_RSH_K, 24}, {RPSTEER_LDX_MEM, 0},
    {RPSTEER_XOR_X, 0},          {RPSTEER_JGE_K, 0},  {RPSTEER_RET_A, 0},
    {RPSTEER_RET_K, 0xffffffff},
};

static void rpsteer_emit_round2_tail(u64* o, u32 k2lo, u32 k2hi, u32 nsock) {
  rpsteer_emit_ops(o, 129, rpsteer_round2, 16);
  o[131] = rpsteer_insn(RPSTEER_MUL_K, 0, 0, k2hi);
  o[136] = rpsteer_insn(RPSTEER_MUL_K, 0, 0, k2lo);
  o[142] = rpsteer_insn(RPSTEER_JGE_K, 1, 0, nsock);
}

usz rpsteer_prog_build(
    u64 out[RPSTEER_PROG_LEN], const ncid_route_key* key, u32 nsock) {
  u32 k1lo = (u32)key->k[1];
  u32 k2lo = (u32)key->k[2];
  rpsteer_emit_head(out);
  rpsteer_emit_cid_load(out);
  rpsteer_emit_w(out, (u32)key->k[0]);
  rpsteer_emit_mulhi(out, 29, k1lo);
  rpsteer_emit_round1_tail(
      out, k1lo, (u32)(key->k[1] >> 32), (u32)(key->k[0] >> 32) * k1lo);
  rpsteer_emit_mulhi(out, 85, k2lo);
  rpsteer_emit_round2_tail(out, k2lo, (u32)(key->k[2] >> 32), nsock);
  return RPSTEER_PROG_LEN;
}
