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

/* Fixed 23-instruction filter template (see xdpbpf.h for the semantics);
 * indices 14 and 16 are patched per call with the port and map fd. */
static void bpf_prog_template(u64 out[QUIC_XDPBPF_PROG_LEN]) {
  out[0]  = bpf_insn(BPF_INSN_LDXW, 2, 1, 0, 0);
  out[1]  = bpf_insn(BPF_INSN_LDXW, 3, 1, 4, 0);
  out[2]  = bpf_insn(BPF_INSN_MOV64_REG, 5, 2, 0, 0);
  out[3]  = bpf_insn(BPF_INSN_ADD64_IMM, 5, 0, 0, 42);
  out[4]  = bpf_insn(BPF_INSN_JGT_REG, 5, 3, 16, 0);
  out[5]  = bpf_insn(BPF_INSN_LDXH, 4, 2, 12, 0);
  out[6]  = bpf_insn(BPF_INSN_JNE_IMM, 4, 0, 14, 0x0008);
  out[7]  = bpf_insn(BPF_INSN_LDXB, 4, 2, 14, 0);
  out[8]  = bpf_insn(BPF_INSN_JNE_IMM, 4, 0, 12, 0x45);
  out[9]  = bpf_insn(BPF_INSN_LDXH, 4, 2, 20, 0);
  out[10] = bpf_insn(BPF_INSN_JSET_IMM, 4, 0, 10, 0xff3f);
  out[11] = bpf_insn(BPF_INSN_LDXB, 4, 2, 23, 0);
  out[12] = bpf_insn(BPF_INSN_JNE_IMM, 4, 0, 8, 17);
  out[13] = bpf_insn(BPF_INSN_LDXH, 4, 2, 36, 0);
  out[14] = bpf_insn(BPF_INSN_JNE_IMM, 4, 0, 6, 0); /* patched: dport */
  out[15] = bpf_insn(BPF_INSN_LDXW, 2, 1, 16, 0);
  out[16] = bpf_insn(BPF_INSN_LDDW_IMM, 1, BPF_SRC_MAP_FD, 0, 0); /* patched */
  out[17] = bpf_insn(0, 0, 0, 0, 0);
  out[18] = bpf_insn(BPF_INSN_MOV64_IMM, 3, 0, 0, XDP_PASS);
  out[19] = bpf_insn(BPF_INSN_CALL, 0, 0, 0, BPF_FUNC_REDIRECT_MAP);
  out[20] = bpf_insn(BPF_INSN_EXIT, 0, 0, 0, 0);
  out[21] = bpf_insn(BPF_INSN_MOV64_IMM, 0, 0, 0, XDP_PASS);
  out[22] = bpf_insn(BPF_INSN_EXIT, 0, 0, 0, 0);
}

usz quic_xdpbpf_prog_build(
    u64 out[QUIC_XDPBPF_PROG_LEN], i32 map_fd, u16 port) {
  bpf_prog_template(out);
  out[14] = bpf_insn(BPF_INSN_JNE_IMM, 4, 0, 6, bpf_htons(port));
  out[16] = bpf_insn(BPF_INSN_LDDW_IMM, 1, BPF_SRC_MAP_FD, 0, map_fd);
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
