#include "transport/io/socket/rpsteer/rpsteer_impl.h"

void rpsteer_emit_ops(u64* o, u32 i, const rpsteer_op* ops, u32 n) {
  for (u32 j = 0; j < n; j++) {
    o[i + j] = rpsteer_insn(ops[j].code, 0, 0, ops[j].k);
  }
}

/* mulhi32, idx i..i+4: split M1 into 16-bit halves a0 (M2) and a1 (M3). */
static const rpsteer_op rpsteer_mulhi_head[5] = {
    {RPSTEER_AND_K, 0xffff}, {RPSTEER_ST_MEM, 2}, {RPSTEER_LD_MEM, 1},
    {RPSTEER_RSH_K, 16},     {RPSTEER_ST_MEM, 3},
};

/* mulhi32, idx i+17..i+43, all operands fixed scratch slots:
 * i+17..i+30: M8 = ((t1 & 0xffff) + (t2 & 0xffff) + (t0 >> 16)) >> 16 --
 * the carry of the middle column, computed without a 33rd bit (each term
 * < 2^16, so the sum is exact in 32 bits);
 * i+31..i+43: A = t3 + (t1 >> 16) + (t2 >> 16) + M8 = the high 32 bits of
 * M1 * b. */
static const rpsteer_op rpsteer_mulhi_tail[27] = {
    {RPSTEER_LD_MEM, 5},  {RPSTEER_AND_K, 0xffff}, {RPSTEER_ST_MEM, 8},
    {RPSTEER_LD_MEM, 6},  {RPSTEER_AND_K, 0xffff}, {RPSTEER_LDX_MEM, 8},
    {RPSTEER_ADD_X, 0},   {RPSTEER_ST_MEM, 8},     {RPSTEER_LD_MEM, 4},
    {RPSTEER_RSH_K, 16},  {RPSTEER_LDX_MEM, 8},    {RPSTEER_ADD_X, 0},
    {RPSTEER_RSH_K, 16},  {RPSTEER_ST_MEM, 8},     {RPSTEER_LD_MEM, 5},
    {RPSTEER_RSH_K, 16},  {RPSTEER_LDX_MEM, 8},    {RPSTEER_ADD_X, 0},
    {RPSTEER_ST_MEM, 8},  {RPSTEER_LD_MEM, 6},     {RPSTEER_RSH_K, 16},
    {RPSTEER_LDX_MEM, 8}, {RPSTEER_ADD_X, 0},      {RPSTEER_ST_MEM, 8},
    {RPSTEER_LD_MEM, 7},  {RPSTEER_LDX_MEM, 8},    {RPSTEER_ADD_X, 0},
};

/* idx i+5..i+16: the four partial products a0*b0, a1*b0, a0*b1, a1*b1 into
 * M4..M7 (each fits 32 bits, so RPSTEER_MUL_K is exact). */
static void rpsteer_emit_mulhi_products(u64* o, u32 i, u32 b) {
  for (u32 j = 0; j < 4; j++) {
    o[i + 5 + 3 * j] = rpsteer_insn(RPSTEER_LD_MEM, 0, 0, 2 + (j & 1));
    o[i + 6 + 3 * j] =
        rpsteer_insn(RPSTEER_MUL_K, 0, 0, j < 2 ? b & 0xffff : b >> 16);
    o[i + 7 + 3 * j] = rpsteer_insn(RPSTEER_ST_MEM, 0, 0, 4 + j);
  }
}

void rpsteer_emit_mulhi(u64* o, u32 i, u32 b) {
  rpsteer_emit_ops(o, i, rpsteer_mulhi_head, 5);
  rpsteer_emit_mulhi_products(o, i, b);
  rpsteer_emit_ops(o, i + 17, rpsteer_mulhi_tail, 27);
}
