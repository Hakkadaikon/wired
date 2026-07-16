#include "transport/io/xdp/xdpbpf/xdpbpf.h"

/* bpf(2) syscall number: not in the shared syscall.h table because only this
 * file uses it (naming-and-unity-build.md: local #define for a single
 * subsystem). Verified against /usr/include/asm/unistd_64.h (__NR_bpf). */
#define SYS_bpf 321

/* linux/bpf.h enum bpf_cmd, verified two ways on this host (6.8.0): (1) hand-
 * counting the enum body at line 883 from BPF_MAP_CREATE=0, (2) compiling a
 * one-line C probe that prints the real macro values <linux/bpf.h> expands
 * to (a manual recount previously miscounted BPF_LINK_CREATE as 29 by double
 * -counting the BPF_PROG_RUN=BPF_PROG_TEST_RUN alias entry -- the compiled
 * probe is the ground truth, not a second manual count). BPF_MAP_CREATE=0,
 * BPF_MAP_UPDATE_ELEM=2, BPF_PROG_LOAD=5, BPF_LINK_CREATE=28. */
#define BPF_MAP_CREATE 0
#define BPF_MAP_UPDATE_ELEM 2
#define BPF_PROG_LOAD 5
#define BPF_LINK_CREATE 28

/* linux/bpf.h enum bpf_map_type: BPF_MAP_TYPE_XSKMAP=17 (line 941, counting
 * from BPF_MAP_TYPE_UNSPEC=0). enum bpf_prog_type: BPF_PROG_TYPE_XDP=6 (line
 * 988, counting from BPF_PROG_TYPE_UNSPEC=0). enum bpf_attach_type:
 * BPF_XDP=37 (line 1056, counting from BPF_CGROUP_INET_INGRESS=0). */
#define BPF_MAP_TYPE_XSKMAP 17
#define BPF_PROG_TYPE_XDP 6
#define BPF_ATTACH_TYPE_XDP 37

/* eBPF instruction opcodes (linux/bpf_common.h + linux/bpf.h): the encoding
 * bytes used by the fixed filter template below. */
#define BPF_INSN_LDXW \
  0x61 /* BPF_LDX|BPF_MEM|BPF_W: r_dst = *(u32*)(r_src+off) */
#define BPF_INSN_LDXH 0x69      /* BPF_LDX|BPF_MEM|BPF_H */
#define BPF_INSN_LDXB 0x71      /* BPF_LDX|BPF_MEM|BPF_B */
#define BPF_INSN_MOV64_REG 0xbf /* BPF_ALU64|BPF_MOV|BPF_X: r_dst = r_src */
#define BPF_INSN_MOV64_IMM 0xb7 /* BPF_ALU64|BPF_MOV|BPF_K: r_dst = imm */
#define BPF_INSN_ADD64_IMM 0x07 /* BPF_ALU64|BPF_ADD|BPF_K: r_dst += imm */
#define BPF_INSN_JGT_REG 0x2d   /* BPF_JMP|BPF_JGT|BPF_X: if r_dst>r_src goto */
#define BPF_INSN_JNE_IMM 0x55   /* BPF_JMP|BPF_JNE|BPF_K: if r_dst!=imm goto */
#define BPF_INSN_JSET_IMM 0x45  /* BPF_JMP|BPF_JSET|BPF_K: if r_dst&imm goto */
#define BPF_INSN_JA 0x05        /* BPF_JMP|BPF_JA: unconditional goto */
#define BPF_INSN_LDDW_IMM 0x18  /* BPF_LD|BPF_DW|BPF_IMM: 16-byte wide load */
#define BPF_INSN_CALL 0x85      /* BPF_JMP|BPF_CALL */
#define BPF_INSN_EXIT 0x95      /* BPF_JMP|BPF_EXIT */

#define BPF_SRC_MAP_FD 1 /* BPF_PSEUDO_MAP_FD: src reg of a map-fd lddw */
#define BPF_FUNC_REDIRECT_MAP 51 /* helper id of bpf_redirect_map() */
#define XDP_PASS 2

/* Pack one 8-byte eBPF instruction: code | dst<<8 | src<<12 | (u16)off<<16 |
 * (u32)imm<<32, matching struct bpf_insn's field layout on little-endian.
 * off is passed as u16 (every jump in this filter is a small forward
 * offset, never negative). */
static u64 bpf_insn(u8 code, u8 dst, u8 src, u16 off, i32 imm) {
  return (u64)code | ((u64)dst << 8) | ((u64)src << 12) | ((u64)off << 16) |
         ((u64)(u32)imm << 32);
}

static u16 bpf_htons(u16 port) {
  return (u16)(((port & 0xffu) << 8) | (port >> 8));
}

/* Fixed instruction indices past the eth/IPv4/UDP/dport prologue (idx 0-14,
 * unchanged from the original 23-instruction filter): where each named block
 * of the core-routing extension starts, so the jump-offset arithmetic below
 * reads as "index of X" rather than a bare number repeated at every use. */
#define BPF_IDX_CORE_START 15 /* short-header boundary check begins */
#define BPF_IDX_CHECK_LONG 21 /* top-bit set: decide short vs long */
#define BPF_IDX_LONG 24       /* long-header path begins */
#define BPF_IDX_HAS_DCID 30   /* long header, DCID len != 0 */
#define BPF_IDX_FALLBACK 32   /* rx_queue_index fallback key load */
#define BPF_IDX_REDIRECT 33   /* map fd load + bpf_redirect_map() call */
#define BPF_IDX_PASS 38       /* dport/boundary miss -> XDP_PASS */

/* off for a forward jump from instruction `from` to instruction `to` (BPF's
 * off field is relative to the instruction AFTER the jump itself). */
static u16 bpf_off(int from, int to) { return (u16)(to - (from + 1)); }

/* idx 0-14: eth/IPv4(IHL=5)/UDP header validate + dport compare, byte-for-
 * byte the original fixed template -- every jump here now targets
 * BPF_IDX_PASS instead of the old idx21, since the redirect-map epilogue
 * moved to make room for the core-routing block. dport itself (idx14) is
 * patched by the caller after this runs. */
static void bpf_prog_prologue(u64 out[QUIC_XDPBPF_PROG_LEN]) {
  out[0] = bpf_insn(BPF_INSN_LDXW, 2, 1, 0, 0);
  out[1] = bpf_insn(BPF_INSN_LDXW, 3, 1, 4, 0);
  out[2] = bpf_insn(BPF_INSN_MOV64_REG, 5, 2, 0, 0);
  out[3] = bpf_insn(BPF_INSN_ADD64_IMM, 5, 0, 0, 42);
  out[4] = bpf_insn(BPF_INSN_JGT_REG, 5, 3, bpf_off(4, BPF_IDX_PASS), 0);
  out[5] = bpf_insn(BPF_INSN_LDXH, 4, 2, 12, 0);
  out[6] = bpf_insn(BPF_INSN_JNE_IMM, 4, 0, bpf_off(6, BPF_IDX_PASS), 0x0008);
  out[7] = bpf_insn(BPF_INSN_LDXB, 4, 2, 14, 0);
  out[8] = bpf_insn(BPF_INSN_JNE_IMM, 4, 0, bpf_off(8, BPF_IDX_PASS), 0x45);
  out[9] = bpf_insn(BPF_INSN_LDXH, 4, 2, 20, 0);
  out[10] =
      bpf_insn(BPF_INSN_JSET_IMM, 4, 0, bpf_off(10, BPF_IDX_PASS), 0xff3f);
  out[11] = bpf_insn(BPF_INSN_LDXB, 4, 2, 23, 0);
  out[12] = bpf_insn(BPF_INSN_JNE_IMM, 4, 0, bpf_off(12, BPF_IDX_PASS), 17);
  out[13] = bpf_insn(BPF_INSN_LDXH, 4, 2, 36, 0);
  out[14] = bpf_insn(BPF_INSN_JNE_IMM, 4, 0, bpf_off(14, BPF_IDX_PASS), 0);
}

/* idx 15-20: short-header boundary check (data+44<=data_end, since the core
 * id byte is at offset 43), read the QUIC header's first byte, and split on
 * its top bit (RFC 9000 17.2/17.3: 1 = long header candidate, 0 = short
 * header -- a top bit of 0 is never valid on the wire this filter expects,
 * so it falls back rather than misreading a non-QUIC byte as a core id). */
static void bpf_prog_header_split(u64 out[QUIC_XDPBPF_PROG_LEN]) {
  int i      = BPF_IDX_CORE_START;
  out[i]     = bpf_insn(BPF_INSN_MOV64_REG, 5, 2, 0, 0);
  out[i + 1] = bpf_insn(BPF_INSN_ADD64_IMM, 5, 0, 0, 44);
  out[i + 2] =
      bpf_insn(BPF_INSN_JGT_REG, 5, 3, bpf_off(i + 2, BPF_IDX_FALLBACK), 0);
  out[i + 3] = bpf_insn(BPF_INSN_LDXB, 4, 2, 42, 0);
  out[i + 4] = bpf_insn(
      BPF_INSN_JSET_IMM, 4, 0, bpf_off(i + 4, BPF_IDX_CHECK_LONG), 0x80);
  out[i + 5] = bpf_insn(BPF_INSN_JA, 0, 0, bpf_off(i + 5, BPF_IDX_FALLBACK), 0);
}

/* idx 21-23: BPF_IDX_CHECK_LONG splits short (top bit 1, next bit 0) from
 * long (both bits 1); the short path reads the DCID's first byte straight
 * out of the fixed short-header layout (offset 43, RFC 9000 17.3) into r2,
 * overwriting the data pointer with the core-routing key -- r2 is dead for
 * data access from here on, same reuse the original template already made
 * of r2 at the old idx15 (rx_queue_index load). */
static void bpf_prog_short_path(u64 out[QUIC_XDPBPF_PROG_LEN]) {
  out[BPF_IDX_CHECK_LONG] = bpf_insn(
      BPF_INSN_JSET_IMM, 4, 0, bpf_off(BPF_IDX_CHECK_LONG, BPF_IDX_LONG), 0x40);
  out[BPF_IDX_CHECK_LONG + 1] = bpf_insn(BPF_INSN_LDXB, 2, 2, 43, 0);
  out[BPF_IDX_CHECK_LONG + 2] = bpf_insn(
      BPF_INSN_JA, 0, 0, bpf_off(BPF_IDX_CHECK_LONG + 2, BPF_IDX_REDIRECT), 0);
}

/* idx 24-31: long-header path (RFC 9000 17.2) -- boundary-check up to
 * offset 49 (version(4) + DCID-len(1) byte + the DCID's own first byte),
 * read the explicit DCID length byte at offset 47, fall back on a
 * zero-length DCID (no core id byte exists then), else read the DCID's
 * first byte at offset 48 into r2 the same way the short path does. */
static void bpf_prog_long_path(u64 out[QUIC_XDPBPF_PROG_LEN]) {
  int i      = BPF_IDX_LONG;
  out[i]     = bpf_insn(BPF_INSN_MOV64_REG, 5, 2, 0, 0);
  out[i + 1] = bpf_insn(BPF_INSN_ADD64_IMM, 5, 0, 0, 49);
  out[i + 2] =
      bpf_insn(BPF_INSN_JGT_REG, 5, 3, bpf_off(i + 2, BPF_IDX_FALLBACK), 0);
  out[i + 3] = bpf_insn(BPF_INSN_LDXB, 4, 2, 47, 0);
  out[i + 4] =
      bpf_insn(BPF_INSN_JNE_IMM, 4, 0, bpf_off(i + 4, BPF_IDX_HAS_DCID), 0);
  out[i + 5] = bpf_insn(BPF_INSN_JA, 0, 0, bpf_off(i + 5, BPF_IDX_FALLBACK), 0);
  out[BPF_IDX_HAS_DCID]     = bpf_insn(BPF_INSN_LDXB, 2, 2, 48, 0);
  out[BPF_IDX_HAS_DCID + 1] = bpf_insn(
      BPF_INSN_JA, 0, 0, bpf_off(BPF_IDX_HAS_DCID + 1, BPF_IDX_REDIRECT), 0);
}

/* idx 32-39: the rx_queue_index fallback key load (BPF_IDX_FALLBACK, the
 * original template's only routing key before this task), then the shared
 * redirect-map epilogue every path above converges on (BPF_IDX_REDIRECT),
 * and finally the XDP_PASS trap every dport/boundary miss above jumps to
 * (BPF_IDX_PASS). map_fd (idx REDIRECT+0/+1, the LDDW) is patched by the
 * caller after this runs, same as the original template's idx16. */
static void bpf_prog_epilogue(u64 out[QUIC_XDPBPF_PROG_LEN]) {
  out[BPF_IDX_FALLBACK] = bpf_insn(BPF_INSN_LDXW, 2, 1, 16, 0);
  out[BPF_IDX_REDIRECT] =
      bpf_insn(BPF_INSN_LDDW_IMM, 1, BPF_SRC_MAP_FD, 0, 0); /* patched */
  out[BPF_IDX_REDIRECT + 1] = bpf_insn(0, 0, 0, 0, 0);
  out[BPF_IDX_REDIRECT + 2] = bpf_insn(BPF_INSN_MOV64_IMM, 3, 0, 0, XDP_PASS);
  out[BPF_IDX_REDIRECT + 3] =
      bpf_insn(BPF_INSN_CALL, 0, 0, 0, BPF_FUNC_REDIRECT_MAP);
  out[BPF_IDX_REDIRECT + 4] = bpf_insn(BPF_INSN_EXIT, 0, 0, 0, 0);
  out[BPF_IDX_PASS]         = bpf_insn(BPF_INSN_MOV64_IMM, 0, 0, 0, XDP_PASS);
  out[BPF_IDX_PASS + 1]     = bpf_insn(BPF_INSN_EXIT, 0, 0, 0, 0);
}

/* Fixed filter template (see xdpbpf.h for the full semantics); dport
 * (idx14) and map_fd (the LDDW at BPF_IDX_REDIRECT) are patched per call by
 * quic_xdpbpf_prog_build. */
static void bpf_prog_template(u64 out[QUIC_XDPBPF_PROG_LEN]) {
  bpf_prog_prologue(out);
  bpf_prog_header_split(out);
  bpf_prog_short_path(out);
  bpf_prog_long_path(out);
  bpf_prog_epilogue(out);
}

usz quic_xdpbpf_prog_build(
    u64 out[QUIC_XDPBPF_PROG_LEN], i32 map_fd, u16 port) {
  bpf_prog_template(out);
  out[14] = bpf_insn(
      BPF_INSN_JNE_IMM, 4, 0, bpf_off(14, BPF_IDX_PASS), bpf_htons(port));
  out[BPF_IDX_REDIRECT] =
      bpf_insn(BPF_INSN_LDDW_IMM, 1, BPF_SRC_MAP_FD, 0, map_fd);
  return QUIC_XDPBPF_PROG_LEN;
}

/* BPF_MAP_CREATE attr (linux/bpf.h:1397), first 5 fields only (20 bytes). */
typedef struct {
  u32 map_type;
  u32 key_size;
  u32 value_size;
  u32 max_entries;
  u32 map_flags;
} bpf_attr_map_create;

i64 quic_xdpbpf_map_create(u32 max_entries) {
  bpf_attr_map_create attr = {BPF_MAP_TYPE_XSKMAP, 4, 4, max_entries, 0};
  return syscall3(SYS_bpf, BPF_MAP_CREATE, &attr, sizeof attr);
}

/* BPF_MAP_UPDATE_ELEM attr (linux/bpf.h:1427): map_fd, then two 8-byte
 * aligned pointers and a u64 flags field (32 bytes). */
typedef struct {
  u32 map_fd;
  u64 key;
  u64 value;
  u64 flags;
} bpf_attr_map_update;

i64 quic_xdpbpf_map_set(i64 map_fd, u32 key, u32 xsk_fd) {
  bpf_attr_map_update attr = {(u32)map_fd, (u64)&key, (u64)&xsk_fd, 0};
  return syscall3(SYS_bpf, BPF_MAP_UPDATE_ELEM, &attr, sizeof attr);
}

/* BPF_PROG_LOAD attr (linux/bpf.h:1454), the fields this SDK sets (40
 * bytes); later fields the kernel doesn't require are omitted. */
typedef struct {
  u32 prog_type;
  u32 insn_cnt;
  u64 insns;
  u64 license;
  u32 log_level;
  u32 log_size;
  u64 log_buf;
} bpf_attr_prog_load;

static void prog_load_attach_log(bpf_attr_prog_load* attr, quic_mspan log) {
  attr->log_level = 1;
  attr->log_size  = (u32)log.n;
  attr->log_buf   = (u64)log.p;
}

i64 quic_xdpbpf_prog_load(const u64* insns, u32 cnt, quic_mspan log) {
  static const u8    license[] = "Dual MIT/GPL";
  bpf_attr_prog_load attr      = {
      BPF_PROG_TYPE_XDP, cnt, (u64)insns, (u64)license, 0, 0, 0};
  if (log.n > 0) prog_load_attach_log(&attr, log);
  return syscall3(SYS_bpf, BPF_PROG_LOAD, &attr, sizeof attr);
}

/* BPF_LINK_CREATE attr (linux/bpf.h:1624), the first 16 bytes (the union's
 * later attach-type-specific fields are unused for BPF_XDP). */
typedef struct {
  u32 prog_fd;
  u32 target_ifindex;
  u32 attach_type;
  u32 flags;
} bpf_attr_link_create;

i64 quic_xdpbpf_link_create(i64 prog_fd, u32 ifindex, u32 flags) {
  bpf_attr_link_create attr = {
      (u32)prog_fd, ifindex, BPF_ATTACH_TYPE_XDP, flags};
  return syscall3(SYS_bpf, BPF_LINK_CREATE, &attr, sizeof attr);
}
