#include "test.h"

/* Golden 58-instruction program for map_fd=5, port=4433 (0x1151, byte-swapped
 * to 0x5111 at idx14) and the route key xbt_key below. Every u64 was produced
 * by an independent Python listing of the layout (code | dst<<8 | src<<12 |
 * (u16)off<<16 | (u32)imm<<32, offsets relative to the next instruction):
 * idx0-14 the eth/IPv4(IHL=5, unfragmented)/UDP/dport prologue, every miss
 * jumping to the XDP_PASS trap at idx56; idx15-19 the short-header bound
 * (data+48) and the Header Form split (0x80 -> long); idx20-22 the short
 * path (r5 = data+43, JA idx31); idx23-30 the long path (bound data+53,
 * DCID length at 47, r5 = data+48); idx31-47 the routing-byte unmask
 * (ncid_route_decode in eBPF, three key LDDWs at 33/36/42); idx48 the
 * key < 64 range check; idx49 the skip to the redirect; idx50 the
 * rx_queue_index fallback; idx51-55 bpf_redirect_map; idx56-57 XDP_PASS. Every
 * branch is forward-only, the property the kernel verifier needs (see
 * bpf_prog_key_check's comment). */
static const ncid_route_key xbt_key = {
    {0x0123456789abcdefULL, 0x9e3779b97f4a7c15ULL, 0xbf58476d1ce4e5b9ULL}};

static const u64 xbt_golden[XDPBPF_PROG_LEN] = {
    0x0000000000001261ULL, 0x0000000000041361ULL, 0x00000000000025bfULL,
    0x0000002a00000507ULL, 0x000000000033352dULL, 0x00000000000c2469ULL,
    0x0000000800310455ULL, 0x00000000000e2471ULL, 0x00000045002f0455ULL,
    0x0000000000142469ULL, 0x0000ff3f002d0445ULL, 0x0000000000172471ULL,
    0x00000011002b0455ULL, 0x0000000000242469ULL, 0x0000511100290455ULL,
    0x00000000000025bfULL, 0x0000003000000507ULL, 0x000000000020352dULL,
    0x00000000002a2471ULL, 0x0000008000030445ULL, 0x00000000000025bfULL,
    0x0000002b00000507ULL, 0x0000000000080005ULL, 0x00000000000025bfULL,
    0x0000003500000507ULL, 0x000000000018352dULL, 0x00000000002f2471ULL,
    0x0000000000010455ULL, 0x0000000000150005ULL, 0x00000000000025bfULL,
    0x0000003000000507ULL, 0x0000000000005671ULL, 0x0000000000015761ULL,
    0x89abcdef00000818ULL, 0x0123456700000000ULL, 0x00000000000087afULL,
    0x7f4a7c1500000818ULL, 0x9e3779b900000000ULL, 0x000000000000872fULL,
    0x00000000000078bfULL, 0x0000002000000877ULL, 0x00000000000087afULL,
    0x1ce4e5b900000818ULL, 0xbf58476d00000000ULL, 0x000000000000872fULL,
    0x0000003800000777ULL, 0x00000000000076afULL, 0x00000000000062bfULL,
    0x0000004000010235ULL, 0x0000000000010005ULL, 0x0000000000101261ULL,
    0x0000000500001118ULL, 0x0000000000000000ULL, 0x00000002000003b7ULL,
    0x0000003300000085ULL, 0x0000000000000095ULL, 0x00000002000000b7ULL,
    0x0000000000000095ULL};

/* The built program matches the golden array exactly. */
static void test_xdpbpf_prog_build_golden(void) {
  u64 out[XDPBPF_PROG_LEN];
  CHECK(xdpbpf_prog_build(out, 5, 4433, &xbt_key) == XDPBPF_PROG_LEN);
  for (usz i = 0; i < XDPBPF_PROG_LEN; i++) {
    CHECK(out[i] == xbt_golden[i]);
  }
}

/* A different map fd, port and key change only idx14 (dport), the six key
 * half-words (33/34, 36/37, 42/43) and idx51 (the map-fd LDDW). */
static void test_xdpbpf_prog_build_patches_only_params(void) {
  static const usz     patched[8] = {14, 33, 34, 36, 37, 42, 43, 51};
  const ncid_route_key k          = {{1, 3, 5}};
  u64                  out[XDPBPF_PROG_LEN];
  usz                  diffs = 0;
  CHECK(xdpbpf_prog_build(out, 9, 1234, &k) == XDPBPF_PROG_LEN);
  for (usz i = 0; i < XDPBPF_PROG_LEN; i++) {
    diffs += out[i] != xbt_golden[i];
  }
  CHECK(diffs == 8);
  for (usz i = 0; i < 8; i++) {
    CHECK(out[patched[i]] != xbt_golden[patched[i]]);
  }
}

/* close fd iff it is a valid (non-negative) descriptor. */
static void xbt_close_if_open(i64 fd) {
  if (fd >= 0) {
    syscall1(SYS_close, fd);
  }
}

/* --- static instruction decode -------------------------------------------
 * Every field of struct xdpbpf_bpf_insn, unpacked from the packed u64 (the
 * exact inverse of xdpbpf.c's xdpbpf_bpf_insn helper) so a test can assert on
 * opcode, registers, jump offset and immediate directly, without a real
 * BPF_PROG_LOAD (CAP_BPF is normally absent in this sandbox). */
typedef struct {
  u8  code;
  u8  dst;
  u8  src;
  u16 off; /* raw bits; BPF's off is actually signed (see xbt_off_signed) */
  i32 imm;
} xbt_insn;

static xbt_insn xbt_decode(u64 v) {
  xbt_insn r;
  r.code = (u8)(v & 0xff);
  r.dst  = (u8)((v >> 8) & 0xf);
  r.src  = (u8)((v >> 12) & 0xf);
  r.off  = (u16)((v >> 16) & 0xffff);
  r.imm  = (i32)(u32)((v >> 32) & 0xffffffff);
  return r;
}

/* BPF_JMP class opcodes that carry a forward `off`: true for every jump this
 * filter ever emits (JGT_REG=0x2d, JGE_IMM=0x35, JNE_IMM=0x55, JSET_IMM=0x45,
 * JA=0x05). Table-driven so a new jump opcode is one row, not another ||. */
static const u8 xbt_jump_codes[] = {0x2d, 0x35, 0x55, 0x45, 0x05};

static int xbt_is_jump(u8 code) {
  for (usz i = 0; i < sizeof xbt_jump_codes; i++) {
    if (xbt_jump_codes[i] == code) {
      return 1;
    }
  }
  return 0;
}

/* BPF's off field is a signed 16-bit value (this repo has no i16 type, so
 * sign-extend the raw u16 by hand). */
static int xbt_off_signed(u16 off) {
  return off >= 0x8000u ? (int)off - 0x10000 : (int)off;
}

/* Every jump instruction's `off`, read out of a built program, lands exactly
 * on the instruction index this test expects -- a direct defense against the
 * classic eBPF bug where adding instructions shifts an existing jump target
 * without its offset being recomputed. idx is the jump's own index in prog;
 * `off` is BPF's own field (relative to idx+1), so the absolute target is
 * idx + 1 + off. */
static void xbt_check_branch(const u64* prog, usz idx, int expect_target) {
  xbt_insn in = xbt_decode(prog[idx]);
  CHECK(xbt_is_jump(in.code));
  CHECK((int)idx + 1 + xbt_off_signed(in.off) == expect_target);
}

/* Every branch this filter emits targets a LATER instruction index than its
 * own -- i.e. the program's control-flow graph has no back edge at all. This
 * is the property that fixed the verifier's "infinite loop detected"
 * rejection (see bpf_prog_key_check's comment): a prior layout had the
 * range check's reject edge jump backward into the fallback block. Checked
 * generically over every jump instruction rather than pinning one pair, so
 * a future edit that reintroduces any backward edge fails here first. */
static void test_xdpbpf_prog_has_no_backward_branch(void) {
  u64 prog[XDPBPF_PROG_LEN];
  CHECK(xdpbpf_prog_build(prog, 5, 4433, &xbt_key) == XDPBPF_PROG_LEN);
  for (usz i = 0; i < XDPBPF_PROG_LEN; i++) {
    xbt_insn in = xbt_decode(prog[i]);
    if (!xbt_is_jump(in.code)) {
      continue;
    }
    CHECK(xbt_off_signed(in.off) >= 0);
  }
}

/* Branch targets of the routing block, decoded from the built program:
 * Header Form 1 goes long (idx23), both header paths reach the unmask block
 * (idx31), every bound miss and the zero-length DCID reach the fallback
 * (idx50), and the range check / skip land on fallback / redirect. */
static void test_xdpbpf_routing_branch_targets(void) {
  u64 prog[XDPBPF_PROG_LEN];
  xdpbpf_prog_build(prog, 5, 4433, &xbt_key);
  xbt_check_branch(prog, 14, 56);
  xbt_check_branch(prog, 17, 50);
  xbt_check_branch(prog, 19, 23);
  xbt_check_branch(prog, 22, 31);
  xbt_check_branch(prog, 25, 50);
  xbt_check_branch(prog, 27, 29);
  xbt_check_branch(prog, 28, 50);
  xbt_check_branch(prog, 48, 50);
  xbt_check_branch(prog, 49, 51);
}

/* --- a reference eBPF interpreter -------------------------------------------
 * Runs the built program over a real frame, so the BPF side of the routing
 * byte is checked against ncid_route_decode (the C side) by execution, not by
 * reading instruction fields. Memory model: the xdp_md context (data,
 * data_end, data_meta, ingress_ifindex, rx_queue_index as u32) lives at
 * XBT_CTX, the packet at XBT_PKT; any packet read outside [data, data_end)
 * fails a CHECK, the access the kernel verifier would have refused. */
#define XBT_CTX 0x100u
#define XBT_PKT 0x10000u
#define XBT_PASS (-1)

typedef struct {
  u64       r[11];
  const u8* pkt;
  usz       n;
  u8        ctx[20];
} xbt_vm;

static u64 xbt_le(const u8* p, int size) {
  u64 v = 0;
  for (int i = size - 1; i >= 0; i--) {
    v = (v << 8) | p[i];
  }
  return v;
}

static u64 xbt_mem(const xbt_vm* vm, u64 a, int size) {
  if (a >= XBT_CTX && a + (u64)size <= XBT_CTX + sizeof vm->ctx) {
    return xbt_le(vm->ctx + (a - XBT_CTX), size);
  }
  CHECK(a >= XBT_PKT && a + (u64)size <= XBT_PKT + vm->n);
  if (a < XBT_PKT || a + (u64)size > XBT_PKT + vm->n) {
    return 0;
  }
  return xbt_le(vm->pkt + (a - XBT_PKT), size);
}

static u64 xbt_simm(i32 imm) { return (u64)(i64)imm; }

/* Execute one ALU/load instruction; 0 if code is not one of them. */
static int xbt_alu(xbt_vm* vm, xbt_insn in) {
  u64* d = &vm->r[in.dst];
  u64  s = vm->r[in.src];
  i64  o = xbt_off_signed(in.off);
  switch (in.code) {
    case 0x61:
      *d = xbt_mem(vm, s + (u64)o, 4);
      return 1;
    case 0x69:
      *d = xbt_mem(vm, s + (u64)o, 2);
      return 1;
    case 0x71:
      *d = xbt_mem(vm, s + (u64)o, 1);
      return 1;
    case 0xbf:
      *d = s;
      return 1;
    case 0xb7:
      *d = xbt_simm(in.imm);
      return 1;
    case 0x07:
      *d += xbt_simm(in.imm);
      return 1;
    case 0xaf:
      *d ^= s;
      return 1;
    case 0x2f:
      *d *= s;
      return 1;
    case 0x77:
      *d >>= (u32)in.imm;
      return 1;
    default:
      return 0;
  }
}

/* 1 iff the conditional/unconditional jump in is taken. */
static int xbt_taken(const xbt_vm* vm, xbt_insn in) {
  u64 d = vm->r[in.dst];
  switch (in.code) {
    case 0x2d:
      return d > vm->r[in.src];
    case 0x35:
      return d >= xbt_simm(in.imm);
    case 0x55:
      return d != xbt_simm(in.imm);
    case 0x45:
      return (d & xbt_simm(in.imm)) != 0;
    default:
      return 1; /* 0x05 JA */
  }
}

/* Run prog over frame (rx_queue_index rxq): the XSKMAP key it redirects
 * with, or XBT_PASS. */
static i64 xbt_run(const u64* prog, const u8* frame, usz n, u32 rxq) {
  xbt_vm vm  = {{0}, frame, n, {0}};
  i64    key = XBT_PASS;
  for (int i = 0; i < 4; i++) {
    vm.ctx[i]      = (u8)((XBT_PKT >> (8 * i)) & 0xff);
    vm.ctx[4 + i]  = (u8)(((XBT_PKT + n) >> (8 * i)) & 0xff);
    vm.ctx[16 + i] = (u8)((rxq >> (8 * i)) & 0xff);
  }
  vm.r[1] = XBT_CTX;
  for (usz pc = 0, steps = 0; pc < XDPBPF_PROG_LEN && steps < 200; steps++) {
    xbt_insn in = xbt_decode(prog[pc]);
    if (xbt_alu(&vm, in)) {
      pc++;
    } else if (in.code == 0x18) {
      vm.r[in.dst] =
          (u64)(u32)in.imm | ((u64)(u32)xbt_decode(prog[pc + 1]).imm << 32);
      pc += 2;
    } else if (in.code == 0x85) {
      CHECK(in.imm == 51 && vm.r[3] == 2); /* bpf_redirect_map, XDP_PASS */
      key     = (i64)(u32)vm.r[2];
      vm.r[0] = 4; /* XDP_REDIRECT */
      pc++;
    } else if (in.code == 0x95) {
      return vm.r[0] == 4 ? key : XBT_PASS;
    } else {
      CHECK(xbt_is_jump(in.code));
      pc += 1 + (usz)(xbt_taken(&vm, in) ? xbt_off_signed(in.off) : 0);
    }
  }
  CHECK(0); /* ran off the end or looped */
  return XBT_PASS;
}

/* Frame 10.7.0.2:5555 -> 10.7.0.1:dport carrying quic (built by the
 * production xdpframe_build: DF set, IHL 5). Returns the frame length. */
static usz xbt_frame(u8* buf, usz cap, u16 dport, const u8* quic, usz qn) {
  const xdpframe_tx m = {
      {0x02, 0x07, 0x00, 0x00, 0x00, 0x01},
      {0x02, 0x07, 0x00, 0x00, 0x00, 0x02},
      {{5555, dport}, {0x0a070002, 0x0a070001}},
      0};
  return xdpframe_build(wired_mspan_of(buf, cap), &m, wired_span_of(quic, qn));
}

static u64 xbt_rand_state = 0x243f6a8885a308d3ULL;

static u8 xbt_rand8(void) {
  xbt_rand_state ^= xbt_rand_state << 13;
  xbt_rand_state ^= xbt_rand_state >> 7;
  xbt_rand_state ^= xbt_rand_state << 17;
  return (u8)(xbt_rand_state >> 32);
}

/* A QUIC packet whose DCID routes to core under key: short header (DCID at
 * byte 1) or long header (version 1, DCID length 8 at byte 5), random
 * elsewhere. Returns its length. */
static usz xbt_quic(u8* q, int is_long, u8 core, const ncid_route_key* k) {
  usz at = is_long ? 6 : 1;
  for (usz i = 0; i < 40; i++) {
    q[i] = xbt_rand8();
  }
  q[0] = is_long ? 0xc0 : 0x40;
  if (is_long) {
    q[1] = 0, q[2] = 0, q[3] = 0, q[4] = 1, q[5] = 8;
  }
  CHECK(ncid_route_encode(q + at, 8, core, k) == 0);
  return 40;
}

/* RFC 9312 2.6 routing, end to end: for random CIDs, random keys and every
 * core 0..63, the BPF program run over the frame redirects to exactly the
 * core ncid_route_encode masked into the CID -- short and long headers. */
static void test_xdpbpf_prog_unmasks_routing_byte(void) {
  u8  q[40], f[128];
  u64 prog[XDPBPF_PROG_LEN];
  for (int round = 0; round < 8; round++) {
    ncid_route_key k;
    for (usz i = 0; i < sizeof k.k; i++) {
      ((u8*)k.k)[i] = xbt_rand8();
    }
    k.k[1] |= 1;
    k.k[2] |= 1;
    xdpbpf_prog_build(prog, 5, 4433, &k);
    for (u8 core = 0; core < 64; core++) {
      usz n = xbt_frame(f, sizeof f, 4433, q, xbt_quic(q, core & 1, core, &k));
      CHECK(xbt_run(prog, f, n, 9) == core);
    }
  }
}

/* The routing byte on the wire is not the core: across CIDs that all route
 * to core 3 under one key, the first DCID byte takes many values (an
 * observer cannot read or correlate the core from it). */
static void test_xdpbpf_routing_byte_hides_core(void) {
  u8  seen[256] = {0}, q[40];
  usz distinct  = 0;
  for (int i = 0; i < 256; i++) {
    xbt_quic(q, 0, 3, &xbt_key);
    distinct += !seen[q[1]];
    seen[q[1]] = 1;
  }
  CHECK(distinct > 100);
}

/* Fallback and pass paths, executed: a decoded key >= 64 (e.g. a client's
 * random Initial DCID), a zero-length long-header DCID and a packet too
 * short for the routing bytes all use rx_queue_index; another port or a
 * fragment is XDP_PASS. */
static void test_xdpbpf_prog_fallback_and_pass(void) {
  u8  q[40], f[128];
  u64 prog[XDPBPF_PROG_LEN];
  usz n;
  xdpbpf_prog_build(prog, 5, 4433, &xbt_key);
  n = xbt_frame(f, sizeof f, 4433, q, xbt_quic(q, 1, 200, &xbt_key));
  CHECK(xbt_run(prog, f, n, 7) == 7);
  xbt_quic(q, 1, 0, &xbt_key);
  q[5] = 0; /* zero-length DCID */
  n    = xbt_frame(f, sizeof f, 4433, q, 40);
  CHECK(xbt_run(prog, f, n, 7) == 7);
  n = xbt_frame(f, sizeof f, 4433, q, 3); /* short header, 3 bytes */
  CHECK(xbt_run(prog, f, n, 7) == 7);
  n = xbt_frame(f, sizeof f, 4434, q, xbt_quic(q, 0, 1, &xbt_key));
  CHECK(xbt_run(prog, f, n, 7) == XBT_PASS);
  n = xbt_frame(f, sizeof f, 4433, q, xbt_quic(q, 0, 1, &xbt_key));
  f[ETH_HDR + 6] |= 0x20; /* MF */
  CHECK(xbt_run(prog, f, n, 7) == XBT_PASS);
}

/* Verifier log for the accept test. A successful load with log_level 1
 * writes the whole per-instruction trace, and the kernel fails the load
 * with ENOSPC when it does not fit -- 256 bytes did not; 64 KiB holds this
 * program's trace with room to spare. Static: too large for the stack. */
#define XBT_ACCEPT_LOG_CAP 65536
static u8 xbt_accept_log[XBT_ACCEPT_LOG_CAP];

/* The golden program (map_fd, port=4433) loads and the verifier accepts it,
 * proving the instruction encoding is correct. */
static void test_xdpbpf_prog_load_accepts_golden(i64 map_fd) {
  u64 prog[XDPBPF_PROG_LEN];
  i64 prog_fd;
  xdpbpf_prog_build(prog, (i32)map_fd, 4433, &xbt_key);
  prog_fd = xdpbpf_prog_load(
      prog, XDPBPF_PROG_LEN,
      wired_mspan_of(xbt_accept_log, sizeof xbt_accept_log));
  CHECK(prog_fd >= 0);
  xbt_close_if_open(prog_fd);
}

/* A program with one corrupted word (insn4's jump offset, the boundary
 * check) is rejected by the verifier. */
static void test_xdpbpf_prog_load_rejects_corrupted(i64 map_fd) {
  u64 bad[XDPBPF_PROG_LEN];
  u8  log[256];
  i64 bad_fd;
  xdpbpf_prog_build(bad, (i32)map_fd, 4433, &xbt_key);
  bad[4] = bad[4] ^ 0x00ffULL;
  bad_fd =
      xdpbpf_prog_load(bad, XDPBPF_PROG_LEN, wired_mspan_of(log, sizeof log));
  CHECK(bad_fd < 0);
  xbt_close_if_open(bad_fd);
}

/* Load the golden program (map_fd=5, port=4433) into the kernel. On this
 * sandboxed host CAP_BPF/CAP_NET_ADMIN is normally absent, so map_create is
 * expected to fail with a negative errno and the test skips the rest (same
 * convention as tests/app/srvpoll_test.c's "sandbox: skip"). */
static void test_xdpbpf_map_and_prog_load(void) {
  i64 map_fd = xdpbpf_map_create(64);
  if (map_fd < 0) {
    return; /* sandbox: skip */
  }
  test_xdpbpf_prog_load_accepts_golden(map_fd);
  test_xdpbpf_prog_load_rejects_corrupted(map_fd);
  xbt_close_if_open(map_fd);
}

void test_xdpbpf(void) {
  test_xdpbpf_prog_build_golden();
  test_xdpbpf_prog_build_patches_only_params();
  test_xdpbpf_map_and_prog_load();
  test_xdpbpf_prog_has_no_backward_branch();
  test_xdpbpf_routing_branch_targets();
  test_xdpbpf_prog_unmasks_routing_byte();
  test_xdpbpf_routing_byte_hides_core();
  test_xdpbpf_prog_fallback_and_pass();
}
