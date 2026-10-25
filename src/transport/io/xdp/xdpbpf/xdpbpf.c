/* linux/bpf.h enum bpf_cmd, verified two ways on this host (6.8.0): (1) hand-
 * counting the enum body at line 883 from BPF_MAP_CREATE=0, (2) compiling a
 * one-line C probe that prints the real macro values <linux/bpf.h> expands
 * to (a manual recount previously miscounted BPF_LINK_CREATE as 29 by double
 * -counting the BPF_PROG_RUN=BPF_PROG_TEST_RUN alias entry -- the compiled
 * probe is the ground truth, not a second manual count). BPF_MAP_CREATE=0,
 * BPF_MAP_UPDATE_ELEM=2, BPF_PROG_LOAD=5, BPF_LINK_CREATE=28. */

/* linux/bpf.h enum bpf_map_type: BPF_MAP_TYPE_XSKMAP=17 (line 941, counting
 * from BPF_MAP_TYPE_UNSPEC=0). enum bpf_prog_type: BPF_PROG_TYPE_XDP=6 (line
 * 988, counting from BPF_PROG_TYPE_UNSPEC=0). enum bpf_attach_type:
 * BPF_XDP=37 (line 1056, counting from BPF_CGROUP_INET_INGRESS=0). */

/* eBPF instruction opcodes (linux/bpf_common.h + linux/bpf.h): the encoding
 * bytes used by the fixed filter template below. */

#include "transport/io/xdp/xdpbpf/xdpbpf_impl.h"

static void bpf_prog_bounds(u64 out[XDPBPF_PROG_LEN]);
static void bpf_prog_ipv4(u64 out[XDPBPF_PROG_LEN]);
static void bpf_prog_udp(u64 out[XDPBPF_PROG_LEN]);

/* Pack one 8-byte eBPF instruction: code | dst<<8 | src<<12 | (u16)off<<16 |
 * (u32)imm<<32, matching struct xdpbpf_bpf_insn's field layout on
 * little-endian. off is passed as u16 (every jump in this filter is a small
 * forward offset, never negative). */
u64 xdpbpf_bpf_insn(u8 code, u8 dst, u8 src, u16 off, i32 imm) {
  return (u64)code | ((u64)dst << 8) | ((u64)src << 12) | ((u64)off << 16) |
         ((u64)(u32)imm << 32);
}

u16 xdpbpf_bpf_htons(u16 port) {
  return (u16)(((port & 0xffu) << 8) | (port >> 8));
}

/* off for a forward jump from instruction `from` to instruction `to` (BPF's
 * off field is relative to the instruction AFTER the jump itself). */
u16 xdpbpf_bpf_off(int from, int to) { return (u16)(to - (from + 1)); }

/* idx 0-14: eth/IPv4(IHL=5)/UDP header validate + dport compare, byte-for-
 * byte the original fixed template -- every jump here now targets
 * BPF_IDX_PASS instead of the old idx21, since the redirect-map epilogue
 * moved to make room for the core-routing block. dport itself (idx14) is
 * patched by the caller after this runs. */
/* idx 0-4: load data/data_end and require 42 bytes (eth+IPv4+UDP). */
static void bpf_prog_bounds(u64 out[XDPBPF_PROG_LEN]) {
  out[0] = xdpbpf_bpf_insn(BPF_INSN_LDXW, 2, 1, 0, 0);
  out[1] = xdpbpf_bpf_insn(BPF_INSN_LDXW, 3, 1, 4, 0);
  out[2] = xdpbpf_bpf_insn(BPF_INSN_MOV64_REG, 5, 2, 0, 0);
  out[3] = xdpbpf_bpf_insn(BPF_INSN_ADD64_IMM, 5, 0, 0, 42);
  out[4] = xdpbpf_bpf_insn(
      BPF_INSN_JGT_REG, 5, 3, xdpbpf_bpf_off(4, BPF_IDX_PASS), 0);
}

/* idx 5-10: EtherType IPv4, IHL=5, not a fragment. */
static void bpf_prog_ipv4(u64 out[XDPBPF_PROG_LEN]) {
  out[5] = xdpbpf_bpf_insn(BPF_INSN_LDXH, 4, 2, 12, 0);
  out[6] = xdpbpf_bpf_insn(
      BPF_INSN_JNE_IMM, 4, 0, xdpbpf_bpf_off(6, BPF_IDX_PASS), 0x0008);
  out[7] = xdpbpf_bpf_insn(BPF_INSN_LDXB, 4, 2, 14, 0);
  out[8] = xdpbpf_bpf_insn(
      BPF_INSN_JNE_IMM, 4, 0, xdpbpf_bpf_off(8, BPF_IDX_PASS), 0x45);
  out[9]  = xdpbpf_bpf_insn(BPF_INSN_LDXH, 4, 2, 20, 0);
  out[10] = xdpbpf_bpf_insn(
      BPF_INSN_JSET_IMM, 4, 0, xdpbpf_bpf_off(10, BPF_IDX_PASS), 0xff3f);
}

/* idx 11-14: protocol UDP and the dport compare (patched by the caller). */
static void bpf_prog_udp(u64 out[XDPBPF_PROG_LEN]) {
  out[11] = xdpbpf_bpf_insn(BPF_INSN_LDXB, 4, 2, 23, 0);
  out[12] = xdpbpf_bpf_insn(
      BPF_INSN_JNE_IMM, 4, 0, xdpbpf_bpf_off(12, BPF_IDX_PASS), 17);
  out[13] = xdpbpf_bpf_insn(BPF_INSN_LDXH, 4, 2, 36, 0);
  out[14] = xdpbpf_bpf_insn(
      BPF_INSN_JNE_IMM, 4, 0, xdpbpf_bpf_off(14, BPF_IDX_PASS), 0);
}

void xdpbpf_bpf_prog_prologue(u64 out[XDPBPF_PROG_LEN]) {
  bpf_prog_bounds(out);
  bpf_prog_ipv4(out);
  bpf_prog_udp(out);
}

/* idx 15-19: short-header boundary check (data+48<=data_end: the DCID's
 * first BPF_DCID_SPAN bytes start at offset 43), read the QUIC header's first
 * byte, and split on the Header Form bit (RFC 9000 17.2/17.3: 1 = long
 * header, 0 = short header). An earlier revision sent Header Form 0 to the
 * fallback and treated 0x80-without-0x40 as "short", so real 1-RTT packets
 * were never routed by CID. */
void xdpbpf_bpf_prog_header_split(u64 out[XDPBPF_PROG_LEN]) {
  int i      = BPF_IDX_CORE_START;
  out[i]     = xdpbpf_bpf_insn(BPF_INSN_MOV64_REG, 5, 2, 0, 0);
  out[i + 1] = xdpbpf_bpf_insn(BPF_INSN_ADD64_IMM, 5, 0, 0, 43 + BPF_DCID_SPAN);
  out[i + 2] = xdpbpf_bpf_insn(
      BPF_INSN_JGT_REG, 5, 3, xdpbpf_bpf_off(i + 2, BPF_IDX_FALLBACK), 0);
  out[i + 3] = xdpbpf_bpf_insn(BPF_INSN_LDXB, 4, 2, 42, 0);
  out[i + 4] = xdpbpf_bpf_insn(
      BPF_INSN_JSET_IMM, 4, 0, xdpbpf_bpf_off(i + 4, BPF_IDX_LONG), 0x80);
}

/* idx 20-22 (BPF_IDX_SHORT): the short path points r5 at the DCID in the
 * fixed short-header layout (offset 43, RFC 9000 17.3) and jumps to the
 * shared unmasking block (BPF_IDX_MIX). */
void xdpbpf_bpf_prog_short_path(u64 out[XDPBPF_PROG_LEN]) {
  int i      = BPF_IDX_SHORT;
  out[i]     = xdpbpf_bpf_insn(BPF_INSN_MOV64_REG, 5, 2, 0, 0);
  out[i + 1] = xdpbpf_bpf_insn(BPF_INSN_ADD64_IMM, 5, 0, 0, 43);
  out[i + 2] =
      xdpbpf_bpf_insn(BPF_INSN_JA, 0, 0, xdpbpf_bpf_off(i + 2, BPF_IDX_MIX), 0);
}

/* Emit the 16-byte LDDW r_dst = imm (imm low half in the first slot's imm,
 * high half in the second's). */
static void bpf_lddw(u64* out, u8 dst, u64 imm) {
  out[0] = xdpbpf_bpf_insn(BPF_INSN_LDDW_IMM, dst, 0, 0, (i32)(u32)imm);
  out[1] = xdpbpf_bpf_insn(0, 0, 0, 0, (i32)(u32)(imm >> 32));
}

/* idx 31-38: load cid[0] into r6 and w = LE cid[1..4] into r7, then
 * r7 = (w ^ k0) * k1 (ncid_route_mask's first round). */
static void bpf_prog_mix_head(u64* out, const ncid_route_key* key) {
  out[0] = xdpbpf_bpf_insn(BPF_INSN_LDXB, 6, 5, 0, 0);
  out[1] = xdpbpf_bpf_insn(BPF_INSN_LDXW, 7, 5, 1, 0);
  bpf_lddw(out + 2, 8, key->k[0]);
  out[4] = xdpbpf_bpf_insn(BPF_INSN_XOR64_REG, 7, 8, 0, 0);
  bpf_lddw(out + 5, 8, key->k[1]);
  out[7] = xdpbpf_bpf_insn(BPF_INSN_MUL64_REG, 7, 8, 0, 0);
}

/* idx 39-47: r7 ^= r7 >> 32; r7 *= k2; mask = r7 >> 56; r2 = cid[0] ^ mask
 * (the routing key), exactly ncid_route_decode. */
static void bpf_prog_mix_tail(u64* out, const ncid_route_key* key) {
  out[0] = xdpbpf_bpf_insn(BPF_INSN_MOV64_REG, 8, 7, 0, 0);
  out[1] = xdpbpf_bpf_insn(BPF_INSN_RSH64_IMM, 8, 0, 0, 32);
  out[2] = xdpbpf_bpf_insn(BPF_INSN_XOR64_REG, 7, 8, 0, 0);
  bpf_lddw(out + 3, 8, key->k[2]);
  out[5] = xdpbpf_bpf_insn(BPF_INSN_MUL64_REG, 7, 8, 0, 0);
  out[6] = xdpbpf_bpf_insn(BPF_INSN_RSH64_IMM, 7, 0, 0, 56);
  out[7] = xdpbpf_bpf_insn(BPF_INSN_XOR64_REG, 6, 7, 0, 0);
  out[8] = xdpbpf_bpf_insn(BPF_INSN_MOV64_REG, 2, 6, 0, 0);
}

/* idx 31-47 (BPF_IDX_MIX): r5 points at a DCID whose first BPF_DCID_SPAN
 * bytes are bounds-checked; recover the core index into r2 (RFC 9312 2.6
 * obfuscated routing byte, see ncid_route_key) and fall into KEY_CHECK. */
void xdpbpf_bpf_prog_mix(u64 out[XDPBPF_PROG_LEN], const ncid_route_key* key) {
  bpf_prog_mix_head(out + BPF_IDX_MIX, key);
  bpf_prog_mix_tail(out + BPF_IDX_MIX + 8, key);
}
