#ifndef TRANSPORT_IO_XDP_XDPBPF_XDPBPF_IMPL_H
#define TRANSPORT_IO_XDP_XDPBPF_XDPBPF_IMPL_H

/* Internal to the xdpbpf*.c pieces of this directory: shared types, macros
 * and the functions and tables more than one piece uses. Not public API. */

#include "transport/io/xdp/xdpbpf/xdpbpf.h"

#define BPF_MAP_CREATE 0
#define BPF_MAP_UPDATE_ELEM 2
#define BPF_PROG_LOAD 5
#define BPF_LINK_CREATE 28
#define BPF_MAP_TYPE_XSKMAP 17
#define BPF_PROG_TYPE_XDP 6
#define BPF_ATTACH_TYPE_XDP 37
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

/* Fixed instruction indices: the eth/IPv4/UDP/dport prologue (idx 0-14),
 * the IPv6 block (idx 15-23), then the redirect keyed by rx_queue_index. */
#define BPF_IDX_DPORT4 14   /* IPv4 dport compare (patched) */
#define BPF_IDX_V4_SKIP 15  /* IPv4 path: jump over the IPv6 block */
#define BPF_IDX_V6 16       /* not IPv4: is it IPv6/UDP to dport? */
#define BPF_IDX_DPORT6 23   /* IPv6 dport compare (patched) */
#define BPF_IDX_REDIRECT 24 /* rx_queue_index key, map fd, redirect call */
#define BPF_IDX_PASS 30     /* dport/boundary miss -> XDP_PASS */

/* BPF_MAP_CREATE attr (linux/bpf.h:1397), first 5 fields only (20 bytes). */
typedef struct {
  u32 map_type;
  u32 key_size;
  u32 value_size;
  u32 max_entries;
  u32 map_flags;
} bpf_attr_map_create;

/* BPF_MAP_UPDATE_ELEM attr (linux/bpf.h:1427): map_fd, then two 8-byte
 * aligned pointers and a u64 flags field (32 bytes). */
typedef struct {
  u32 map_fd;
  u64 key;
  u64 value;
  u64 flags;
} bpf_attr_map_update;

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

/* BPF_LINK_CREATE attr (linux/bpf.h:1624), the first 16 bytes (the union's
 * later attach-type-specific fields are unused for BPF_XDP). */
typedef struct {
  u32 prog_fd;
  u32 target_ifindex;
  u32 attach_type;
  u32 flags;
} bpf_attr_link_create;

u64  xdpbpf_bpf_insn(u8 code, u8 dst, u8 src, u16 off, i32 imm);
u16  xdpbpf_bpf_htons(u16 port);
u16  xdpbpf_bpf_off(int from, int to);
void xdpbpf_bpf_prog_prologue(u64 out[XDPBPF_PROG_LEN]);

#endif
