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
static void bpf_prog_ipv6(u64 out[XDPBPF_PROG_LEN]);
static void bpf_prog_ipv6_udp(u64 out[XDPBPF_PROG_LEN]);

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

/* idx 0-14: eth/IPv4(IHL=5)/UDP header validate + dport compare; every
 * miss jumps to BPF_IDX_PASS. dport itself (idx14) is patched by the
 * caller after this runs. */
/* idx 0-4: load data/data_end and require 42 bytes (eth+IPv4+UDP). */
static void bpf_prog_bounds(u64 out[XDPBPF_PROG_LEN]) {
  out[0] = xdpbpf_bpf_insn(BPF_INSN_LDXW, 2, 1, 0, 0);
  out[1] = xdpbpf_bpf_insn(BPF_INSN_LDXW, 3, 1, 4, 0);
  out[2] = xdpbpf_bpf_insn(BPF_INSN_MOV64_REG, 5, 2, 0, 0);
  out[3] = xdpbpf_bpf_insn(BPF_INSN_ADD64_IMM, 5, 0, 0, 42);
  out[4] = xdpbpf_bpf_insn(
      BPF_INSN_JGT_REG, 5, 3, xdpbpf_bpf_off(4, BPF_IDX_PASS), 0);
}

/* idx 5-10: EtherType IPv4 (any other goes to the IPv6 block), IHL=5, not
 * a fragment. */
static void bpf_prog_ipv4(u64 out[XDPBPF_PROG_LEN]) {
  out[5] = xdpbpf_bpf_insn(BPF_INSN_LDXH, 4, 2, 12, 0);
  out[6] = xdpbpf_bpf_insn(
      BPF_INSN_JNE_IMM, 4, 0, xdpbpf_bpf_off(6, BPF_IDX_V6), 0x0008);
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

/* idx 15-23: the IPv4 path jumps over this block; anything else must be
 * EtherType IPv6 (0x86DD, read little-endian as 0xdd86), hold the 62 bytes
 * of eth + IPv6 + UDP, carry Next Header UDP (RFC 8200 4: an extension
 * header or any other protocol passes to the kernel, ICMPv6 neighbour
 * discovery included) and the dport (patched by the caller), then falls
 * into the redirect. */
static void bpf_prog_ipv6(u64 out[XDPBPF_PROG_LEN]) {
  int i                = BPF_IDX_V6;
  out[BPF_IDX_V4_SKIP] = xdpbpf_bpf_insn(
      BPF_INSN_JA, 0, 0, xdpbpf_bpf_off(BPF_IDX_V4_SKIP, BPF_IDX_REDIRECT), 0);
  out[i] = xdpbpf_bpf_insn(
      BPF_INSN_JNE_IMM, 4, 0, xdpbpf_bpf_off(i, BPF_IDX_PASS), 0xdd86);
  out[i + 1] = xdpbpf_bpf_insn(BPF_INSN_MOV64_REG, 5, 2, 0, 0);
  out[i + 2] = xdpbpf_bpf_insn(BPF_INSN_ADD64_IMM, 5, 0, 0, 62);
  out[i + 3] = xdpbpf_bpf_insn(
      BPF_INSN_JGT_REG, 5, 3, xdpbpf_bpf_off(i + 3, BPF_IDX_PASS), 0);
  bpf_prog_ipv6_udp(out);
}

/* idx 20-23: Next Header UDP and the dport (patched). */
static void bpf_prog_ipv6_udp(u64 out[XDPBPF_PROG_LEN]) {
  int i      = BPF_IDX_V6;
  out[i + 4] = xdpbpf_bpf_insn(BPF_INSN_LDXB, 4, 2, 20, 0);
  out[i + 5] = xdpbpf_bpf_insn(
      BPF_INSN_JNE_IMM, 4, 0, xdpbpf_bpf_off(i + 5, BPF_IDX_PASS), 17);
  out[i + 6]          = xdpbpf_bpf_insn(BPF_INSN_LDXH, 4, 2, 56, 0);
  out[BPF_IDX_DPORT6] = xdpbpf_bpf_insn(
      BPF_INSN_JNE_IMM, 4, 0, xdpbpf_bpf_off(BPF_IDX_DPORT6, BPF_IDX_PASS), 0);
}

void xdpbpf_bpf_prog_prologue(u64 out[XDPBPF_PROG_LEN]) {
  bpf_prog_bounds(out);
  bpf_prog_ipv4(out);
  bpf_prog_udp(out);
  bpf_prog_ipv6(out);
}
