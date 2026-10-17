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
#define BPF_INSN_JGE_IMM 0x35   /* BPF_JMP|BPF_JGE|BPF_K: if r_dst>=imm goto */
#define BPF_INSN_JNE_IMM 0x55   /* BPF_JMP|BPF_JNE|BPF_K: if r_dst!=imm goto */
#define BPF_INSN_JSET_IMM 0x45  /* BPF_JMP|BPF_JSET|BPF_K: if r_dst&imm goto */
#define BPF_INSN_JA 0x05        /* BPF_JMP|BPF_JA: unconditional goto */
#define BPF_INSN_LDDW_IMM 0x18  /* BPF_LD|BPF_DW|BPF_IMM: 16-byte wide load */
#define BPF_INSN_CALL 0x85      /* BPF_JMP|BPF_CALL */
#define BPF_INSN_EXIT 0x95      /* BPF_JMP|BPF_EXIT */
#define BPF_SRC_MAP_FD 1 /* BPF_PSEUDO_MAP_FD: src reg of a map-fd lddw */
#define BPF_FUNC_REDIRECT_MAP 51 /* helper id of bpf_redirect_map() */
#define XDP_PASS 2

/* Fixed instruction indices past the eth/IPv4/UDP/dport prologue (idx 0-14,
 * unchanged from the original 23-instruction filter): where each named block
 * of the core-routing extension starts, so the jump-offset arithmetic below
 * reads as "index of X" rather than a bare number repeated at every use. */
#define BPF_IDX_CORE_START 15 /* short-header boundary check begins */
#define BPF_IDX_CHECK_LONG 21 /* top-bit set: decide short vs long */
#define BPF_IDX_LONG 24       /* long-header path begins */
#define BPF_IDX_HAS_DCID 30   /* long header, DCID len != 0 */
#define BPF_IDX_KEY_CHECK 32  /* DCID-byte key range check (< map size) */
#define BPF_IDX_KEY_SKIP 33   /* key in range: skip the fallback load */
#define BPF_IDX_FALLBACK 34   /* rx_queue_index fallback key load */
#define BPF_IDX_REDIRECT 35   /* map fd load + bpf_redirect_map() call */
#define BPF_IDX_PASS 40       /* dport/boundary miss -> XDP_PASS */

/* Number of XSKMAP slots the DCID-byte routing key must stay under. The
 * server-side XSKMAP is always sized WIRED_SRVXDPBPF_MAP_ENTRIES
 * (app/http3/server/srvxdpbpf/srvxdpbpf.h), currently 64; a client's
 * self-chosen initial DCID (RFC 9000 7.2) is an unconstrained random byte,
 * so the key this filter reads is NOT guaranteed to fall inside the map --
 * unlike the fallback key (rx_queue_index), which stays under the RX queue
 * count and is assumed in-range (see BPF_IDX_KEY_CHECK's comment). Kept as
 * a fixed constant here rather than a xdpbpf_prog_build() parameter: this
 * transport-layer file has exactly one caller and must not depend on the
 * app-layer header that owns WIRED_SRVXDPBPF_MAP_ENTRIES. */
#define BPF_XSKMAP_ENTRIES 64

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
void xdpbpf_bpf_prog_header_split(u64 out[XDPBPF_PROG_LEN]);
void xdpbpf_bpf_prog_short_path(u64 out[XDPBPF_PROG_LEN]);

#endif
