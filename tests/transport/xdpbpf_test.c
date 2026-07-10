#include "test.h"

/* Golden 23-instruction program for map_fd=5, port=4433 (0x1151, byte-swapped
 * to 0x5111 at idx14). Every u64 is hand-computed from xdpbpf.h's field
 * layout (code | dst<<8 | src<<12 | (u16)off<<16 | (u32)imm<<32); see the
 * task plan's instruction table for the semantics of each index. */
static const u64 xbt_golden[QUIC_XDPBPF_PROG_LEN] = {
    0x0000000000001261ULL, 0x0000000000041361ULL, 0x00000000000025bfULL,
    0x0000002a00000507ULL, 0x000000000010352dULL, 0x00000000000c2469ULL,
    0x00000008000e0455ULL, 0x00000000000e2471ULL, 0x00000045000c0455ULL,
    0x0000000000142469ULL, 0x0000ff3f000a0445ULL, 0x0000000000172471ULL,
    0x0000001100080455ULL, 0x0000000000242469ULL, 0x0000511100060455ULL,
    0x0000000000101261ULL, 0x0000000500001118ULL, 0x0000000000000000ULL,
    0x00000002000003b7ULL, 0x0000003300000085ULL, 0x0000000000000095ULL,
    0x00000002000000b7ULL, 0x0000000000000095ULL};

/* The built program matches the hand-computed golden array exactly,
 * including the byte-swapped port at idx14 and the map fd at idx16. */
static void test_xdpbpf_prog_build_golden(void) {
  u64 out[QUIC_XDPBPF_PROG_LEN];
  CHECK(quic_xdpbpf_prog_build(out, 5, 4433) == QUIC_XDPBPF_PROG_LEN);
  for (usz i = 0; i < QUIC_XDPBPF_PROG_LEN; i++) CHECK(out[i] == xbt_golden[i]);
}

/* Rebuilding with a different map fd and port changes only idx14 and idx16;
 * every other instruction is byte-identical to the golden program. */
static void test_xdpbpf_prog_build_patches_two_words(void) {
  u64 out[QUIC_XDPBPF_PROG_LEN];
  usz diffs = 0;
  CHECK(quic_xdpbpf_prog_build(out, 9, 1234) == QUIC_XDPBPF_PROG_LEN);
  for (usz i = 0; i < QUIC_XDPBPF_PROG_LEN; i++)
    if (out[i] != xbt_golden[i]) diffs++;
  CHECK(diffs == 2);
  CHECK(out[14] != xbt_golden[14]);
  CHECK(out[16] != xbt_golden[16]);
}

/* close fd iff it is a valid (non-negative) descriptor. */
static void xbt_close_if_open(i64 fd) {
  if (fd >= 0) syscall1(SYS_close, fd);
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
}
