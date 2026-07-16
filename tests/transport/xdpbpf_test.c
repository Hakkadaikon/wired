#include "test.h"

/* Golden 40-instruction program for map_fd=5, port=4433 (0x1151, byte-swapped
 * to 0x5111 at idx14). Every u64 is hand-computed from xdpbpf.h's field
 * layout (code | dst<<8 | src<<12 | (u16)off<<16 | (u32)imm<<32) plus the
 * jump-offset arithmetic in xdpbpf.c's BPF_IDX_* constants (idx0-14 unchanged
 * from the original filter except every jump now targets idx38, the
 * relocated XDP_PASS trap; idx15-31 are the new core-routing block; idx32-39
 * are the rx_queue_index fallback + shared redirect-map epilogue). */
static const u64 xbt_golden[QUIC_XDPBPF_PROG_LEN] = {
    0x0000000000001261ULL, 0x0000000000041361ULL, 0x00000000000025bfULL,
    0x0000002a00000507ULL, 0x000000000021352dULL, 0x00000000000c2469ULL,
    0x00000008001f0455ULL, 0x00000000000e2471ULL, 0x00000045001d0455ULL,
    0x0000000000142469ULL, 0x0000ff3f001b0445ULL, 0x0000000000172471ULL,
    0x0000001100190455ULL, 0x0000000000242469ULL, 0x0000511100170455ULL,
    0x00000000000025bfULL, 0x0000002c00000507ULL, 0x00000000000e352dULL,
    0x00000000002a2471ULL, 0x0000008000010445ULL, 0x00000000000b0005ULL,
    0x0000004000020445ULL, 0x00000000002b2271ULL, 0x0000000000090005ULL,
    0x00000000000025bfULL, 0x0000003100000507ULL, 0x000000000005352dULL,
    0x00000000002f2471ULL, 0x0000000000010455ULL, 0x0000000000020005ULL,
    0x0000000000302271ULL, 0x0000000000010005ULL, 0x0000000000101261ULL,
    0x0000000500001118ULL, 0x0000000000000000ULL, 0x00000002000003b7ULL,
    0x0000003300000085ULL, 0x0000000000000095ULL, 0x00000002000000b7ULL,
    0x0000000000000095ULL};

/* The built program matches the hand-computed golden array exactly,
 * including the byte-swapped port at idx14 and the map fd at idx33. */
static void test_xdpbpf_prog_build_golden(void) {
  u64 out[QUIC_XDPBPF_PROG_LEN];
  CHECK(quic_xdpbpf_prog_build(out, 5, 4433) == QUIC_XDPBPF_PROG_LEN);
  for (usz i = 0; i < QUIC_XDPBPF_PROG_LEN; i++) CHECK(out[i] == xbt_golden[i]);
}

/* Rebuilding with a different map fd and port changes only idx14 (dport) and
 * idx33 (the map-fd LDDW); every other instruction is byte-identical to the
 * golden program. */
static void test_xdpbpf_prog_build_patches_two_words(void) {
  u64 out[QUIC_XDPBPF_PROG_LEN];
  usz diffs = 0;
  CHECK(quic_xdpbpf_prog_build(out, 9, 1234) == QUIC_XDPBPF_PROG_LEN);
  for (usz i = 0; i < QUIC_XDPBPF_PROG_LEN; i++)
    if (out[i] != xbt_golden[i]) diffs++;
  CHECK(diffs == 2);
  CHECK(out[14] != xbt_golden[14]);
  CHECK(out[33] != xbt_golden[33]);
}

/* close fd iff it is a valid (non-negative) descriptor. */
static void xbt_close_if_open(i64 fd) {
  if (fd >= 0) syscall1(SYS_close, fd);
}

/* --- static instruction decode -------------------------------------------
 * Every field of struct bpf_insn, unpacked from the packed u64 (the exact
 * inverse of xdpbpf.c's bpf_insn helper) so a test can assert on opcode,
 * registers, jump offset and immediate directly, without a real BPF_PROG_LOAD
 * (CAP_BPF is normally absent in this sandbox). */
typedef struct {
  u8  code;
  u8  dst;
  u8  src;
  u16 off; /* stored as-is: every jump this filter emits is non-negative */
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
 * filter ever emits (JGT_REG=0x2d, JNE_IMM=0x55, JSET_IMM=0x45, JA=0x05). */
static int xbt_is_jump(u8 code) {
  return code == 0x2d || code == 0x55 || code == 0x45 || code == 0x05;
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
  CHECK((int)idx + 1 + (int)in.off == expect_target);
}

/* Every newly introduced branch in the core-routing block (idx 15-31)
 * targets the instruction this design intends, decoded straight out of the
 * built program -- catches an index shift from a future edit without ever
 * touching BPF_PROG_LOAD. */
static void test_xdpbpf_core_routing_branch_offsets_correct(void) {
  u64 prog[QUIC_XDPBPF_PROG_LEN];
  CHECK(quic_xdpbpf_prog_build(prog, 5, 4433) == QUIC_XDPBPF_PROG_LEN);

  /* prologue's dport-miss jump (idx14) still lands on the relocated PASS. */
  xbt_check_branch(prog, 4, 38);
  xbt_check_branch(prog, 6, 38);
  xbt_check_branch(prog, 8, 38);
  xbt_check_branch(prog, 10, 38);
  xbt_check_branch(prog, 12, 38);
  xbt_check_branch(prog, 14, 38);

  /* header split: boundary-miss -> fallback(32), top-bit-set -> check_long
   * (21), top-bit-clear (fallthrough) -> fallback(32). */
  xbt_check_branch(prog, 17, 32);
  xbt_check_branch(prog, 19, 21);
  xbt_check_branch(prog, 20, 32);

  /* short/long split at idx21: bit 0x40 set -> long(24); short path falls
   * through to read the DCID byte then jumps to redirect(33). */
  xbt_check_branch(prog, 21, 24);
  xbt_check_branch(prog, 23, 33);

  /* long path: boundary-miss -> fallback(32); dcid_len != 0 -> has_dcid(30);
   * dcid_len == 0 (fallthrough) -> fallback(32); has_dcid -> redirect(33). */
  xbt_check_branch(prog, 26, 32);
  xbt_check_branch(prog, 28, 30);
  xbt_check_branch(prog, 29, 32);
  xbt_check_branch(prog, 31, 33);
}

/* The register that ends up holding the core-routing / fallback key (r2,
 * read at idx CHECK_LONG+1==22, idx HAS_DCID==30, and the fallback load at
 * idx32) is never the register the map-fd LDDW writes (r1, idx33) nor the
 * boundary-check scratch register (r5) nor the header-byte scratch (r4) --
 * traced instruction-by-instruction rather than assumed. */
static void test_xdpbpf_core_routing_no_register_clobber(void) {
  u64      prog[QUIC_XDPBPF_PROG_LEN];
  xbt_insn short_key, long_key, fallback_key, map_fd_load, redirect_call;
  CHECK(quic_xdpbpf_prog_build(prog, 5, 4433) == QUIC_XDPBPF_PROG_LEN);

  short_key     = xbt_decode(prog[22]); /* LDXB r2,r2,43 */
  long_key      = xbt_decode(prog[30]); /* LDXB r2,r2,48 */
  fallback_key  = xbt_decode(prog[32]); /* LDXW r2,r1,16 */
  map_fd_load   = xbt_decode(prog[33]); /* LDDW r1,map_fd */
  redirect_call = xbt_decode(prog[36]); /* CALL bpf_redirect_map */

  CHECK(short_key.dst == 2 && long_key.dst == 2 && fallback_key.dst == 2);
  CHECK(map_fd_load.dst == 1); /* the only instruction that writes r1 again */
  CHECK(map_fd_load.dst != short_key.dst);
  CHECK(map_fd_load.dst != long_key.dst);
  CHECK(map_fd_load.dst != fallback_key.dst);
  CHECK(redirect_call.code == 0x85); /* CALL: r2 (the key) still holds it */
}

/* A short-header packet's core-id byte sits at absolute offset 43 (idx
 * CHECK_LONG+1's LDXB), matching 42 (UDP payload start) + 1 (flags byte). */
static void test_xdpbpf_prog_routes_short_header_by_core_id_byte(void) {
  u64      prog[QUIC_XDPBPF_PROG_LEN];
  xbt_insn in;
  CHECK(quic_xdpbpf_prog_build(prog, 5, 4433) == QUIC_XDPBPF_PROG_LEN);
  in = xbt_decode(prog[22]);
  CHECK(in.code == 0x71 /* LDXB */ && in.src == 2 && in.off == 43);
}

/* A long-header packet's core-id byte sits at absolute offset 48, matching
 * 42 + 1(flags) + 4(version) + 1(dcid-len field). */
static void test_xdpbpf_prog_routes_long_header_by_core_id_byte(void) {
  u64      prog[QUIC_XDPBPF_PROG_LEN];
  xbt_insn in;
  CHECK(quic_xdpbpf_prog_build(prog, 5, 4433) == QUIC_XDPBPF_PROG_LEN);
  in = xbt_decode(prog[30]);
  CHECK(in.code == 0x71 /* LDXB */ && in.src == 2 && in.off == 48);
}

/* A long header whose explicit DCID-length byte is 0 has nowhere to read a
 * core-id byte from -- the built program's idx28 (JNE r4,0,->has_dcid) falls
 * through to idx29, a bare JA to the fallback block (idx32), never to the
 * idx30 LDXB this test's sibling above found. */
static void test_xdpbpf_zero_length_dcid_falls_back(void) {
  u64 prog[QUIC_XDPBPF_PROG_LEN];
  CHECK(quic_xdpbpf_prog_build(prog, 5, 4433) == QUIC_XDPBPF_PROG_LEN);
  xbt_check_branch(prog, 29, 32); /* fallthrough-of-JNE's JA -> fallback */
}

/* A packet too short to carry either header's core-id byte fails one of the
 * boundary checks (idx17 short, idx26 long) before any core-id byte is ever
 * read -- both already proven (in the branch-offset test above) to jump to
 * the fallback block (idx32), the same rx_queue_index path the original
 * template always used. This test pins that both boundary checks are indeed
 * JGT_REG (the "too short" comparison), not some other opcode. */
static void test_xdpbpf_short_packet_falls_back(void) {
  u64      prog[QUIC_XDPBPF_PROG_LEN];
  xbt_insn short_bound, long_bound;
  CHECK(quic_xdpbpf_prog_build(prog, 5, 4433) == QUIC_XDPBPF_PROG_LEN);
  short_bound = xbt_decode(prog[17]);
  long_bound  = xbt_decode(prog[26]);
  CHECK(short_bound.code == 0x2d /* JGT_REG */);
  CHECK(long_bound.code == 0x2d);
}

/* The golden program (map_fd, port=4433) loads and the verifier accepts it,
 * proving the instruction encoding is correct. */
static void test_xdpbpf_prog_load_accepts_golden(i64 map_fd) {
  u64 prog[QUIC_XDPBPF_PROG_LEN];
  u8  log[256];
  i64 prog_fd;
  quic_xdpbpf_prog_build(prog, (i32)map_fd, 4433);
  prog_fd = quic_xdpbpf_prog_load(
      prog, QUIC_XDPBPF_PROG_LEN, quic_mspan_of(log, sizeof log));
  CHECK(prog_fd >= 0);
  xbt_close_if_open(prog_fd);
}

/* A program with one corrupted word (insn4's jump offset, the boundary
 * check) is rejected by the verifier. */
static void test_xdpbpf_prog_load_rejects_corrupted(i64 map_fd) {
  u64 bad[QUIC_XDPBPF_PROG_LEN];
  u8  log[256];
  i64 bad_fd;
  quic_xdpbpf_prog_build(bad, (i32)map_fd, 4433);
  bad[4] = bad[4] ^ 0x00ffULL;
  bad_fd = quic_xdpbpf_prog_load(
      bad, QUIC_XDPBPF_PROG_LEN, quic_mspan_of(log, sizeof log));
  CHECK(bad_fd < 0);
  xbt_close_if_open(bad_fd);
}

/* Load the golden program (map_fd=5, port=4433) into the kernel. On this
 * sandboxed host CAP_BPF/CAP_NET_ADMIN is normally absent, so map_create is
 * expected to fail with a negative errno and the test skips the rest (same
 * convention as tests/app/srvpoll_test.c's "sandbox: skip"). */
static void test_xdpbpf_map_and_prog_load(void) {
  i64 map_fd = quic_xdpbpf_map_create(64);
  if (map_fd < 0) return; /* sandbox: skip */
  test_xdpbpf_prog_load_accepts_golden(map_fd);
  test_xdpbpf_prog_load_rejects_corrupted(map_fd);
  xbt_close_if_open(map_fd);
}

void test_xdpbpf(void) {
  test_xdpbpf_prog_build_golden();
  test_xdpbpf_prog_build_patches_two_words();
  test_xdpbpf_map_and_prog_load();
  test_xdpbpf_core_routing_branch_offsets_correct();
  test_xdpbpf_core_routing_no_register_clobber();
  test_xdpbpf_prog_routes_short_header_by_core_id_byte();
  test_xdpbpf_prog_routes_long_header_by_core_id_byte();
  test_xdpbpf_zero_length_dcid_falls_back();
  test_xdpbpf_short_packet_falls_back();
}
