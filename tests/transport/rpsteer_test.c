#include "test.h"
#include "test_sys.h"

/* Golden 145-instruction reuseport selection program for nsock=4 and the
 * same fixed key xdpbpf_test pins (rpst_key below). Produced by an
 * independent hosted prototype of the instruction layout (sock_filter
 * packed as code | jt<<16 | jf<<24 | k<<32) that was validated two ways
 * before being frozen here: (a) an interpreter run against the 64-bit
 * ncid_route_decode reference over 200k random keys/packets, (b) attached
 * to a real 4-socket reuseport group via SO_ATTACH_REUSEPORT_CBPF, with
 * short- and long-header QUIC payloads landing on the socket their DCID
 * encodes. */
static const ncid_route_key rpst_key = {
    {0x0123456789abcdefULL, 0x9e3779b97f4a7c15ULL, 0xbf58476d1ce4e5b9ULL}};

static const u64 rpst_golden[RPSTEER_PROG_LEN] = {
    0x0000000000000080ULL, 0x000000068e000035ULL, 0x0000000000000030ULL,
    0x0000008000020045ULL, 0x0000000100000001ULL, 0x0000000300000005ULL,
    0x0000000000000080ULL, 0x0000000b88000035ULL, 0x0000000600000001ULL,
    0x0000000000000050ULL, 0x0000000000000002ULL, 0x0000000100000050ULL,
    0x0000000100000002ULL, 0x0000000200000050ULL, 0x0000000200000002ULL,
    0x0000000300000050ULL, 0x0000000300000002ULL, 0x0000000400000050ULL,
    0x0000000800000064ULL, 0x0000000300000061ULL, 0x000000000000004cULL,
    0x0000000800000064ULL, 0x0000000200000061ULL, 0x000000000000004cULL,
    0x0000000800000064ULL, 0x0000000100000061ULL, 0x000000000000004cULL,
    0x89abcdef000000a4ULL, 0x0000000100000002ULL, 0x0000ffff00000054ULL,
    0x0000000200000002ULL, 0x0000000100000060ULL, 0x0000001000000074ULL,
    0x0000000300000002ULL, 0x0000000200000060ULL, 0x00007c1500000024ULL,
    0x0000000400000002ULL, 0x0000000300000060ULL, 0x00007c1500000024ULL,
    0x0000000500000002ULL, 0x0000000200000060ULL, 0x00007f4a00000024ULL,
    0x0000000600000002ULL, 0x0000000300000060ULL, 0x00007f4a00000024ULL,
    0x0000000700000002ULL, 0x0000000500000060ULL, 0x0000ffff00000054ULL,
    0x0000000800000002ULL, 0x0000000600000060ULL, 0x0000ffff00000054ULL,
    0x0000000800000061ULL, 0x000000000000000cULL, 0x0000000800000002ULL,
    0x0000000400000060ULL, 0x0000001000000074ULL, 0x0000000800000061ULL,
    0x000000000000000cULL, 0x0000001000000074ULL, 0x0000000800000002ULL,
    0x0000000500000060ULL, 0x0000001000000074ULL, 0x0000000800000061ULL,
    0x000000000000000cULL, 0x0000000800000002ULL, 0x0000000600000060ULL,
    0x0000001000000074ULL, 0x0000000800000061ULL, 0x000000000000000cULL,
    0x0000000800000002ULL, 0x0000000700000060ULL, 0x0000000800000061ULL,
    0x000000000000000cULL, 0x0000000800000002ULL, 0x0000000100000060ULL,
    0x9e3779b900000024ULL, 0x0000000800000061ULL, 0x000000000000000cULL,
    0x5648957300000004ULL, 0x0000000900000002ULL, 0x0000000100000060ULL,
    0x7f4a7c1500000024ULL, 0x0000000900000061ULL, 0x00000000000000acULL,
    0x0000000100000002ULL, 0x0000ffff00000054ULL, 0x0000000200000002ULL,
    0x0000000100000060ULL, 0x0000001000000074ULL, 0x0000000300000002ULL,
    0x0000000200000060ULL, 0x0000e5b900000024ULL, 0x0000000400000002ULL,
    0x0000000300000060ULL, 0x0000e5b900000024ULL, 0x0000000500000002ULL,
    0x0000000200000060ULL, 0x00001ce400000024ULL, 0x0000000600000002ULL,
    0x0000000300000060ULL, 0x00001ce400000024ULL, 0x0000000700000002ULL,
    0x0000000500000060ULL, 0x0000ffff00000054ULL, 0x0000000800000002ULL,
    0x0000000600000060ULL, 0x0000ffff00000054ULL, 0x0000000800000061ULL,
    0x000000000000000cULL, 0x0000000800000002ULL, 0x0000000400000060ULL,
    0x0000001000000074ULL, 0x0000000800000061ULL, 0x000000000000000cULL,
    0x0000001000000074ULL, 0x0000000800000002ULL, 0x0000000500000060ULL,
    0x0000001000000074ULL, 0x0000000800000061ULL, 0x000000000000000cULL,
    0x0000000800000002ULL, 0x0000000600000060ULL, 0x0000001000000074ULL,
    0x0000000800000061ULL, 0x000000000000000cULL, 0x0000000800000002ULL,
    0x0000000700000060ULL, 0x0000000800000061ULL, 0x000000000000000cULL,
    0x0000000800000002ULL, 0x0000000100000060ULL, 0xbf58476d00000024ULL,
    0x0000000800000061ULL, 0x000000000000000cULL, 0x0000000800000002ULL,
    0x0000000900000060ULL, 0x1ce4e5b900000024ULL, 0x0000000800000061ULL,
    0x000000000000000cULL, 0x0000001800000074ULL, 0x0000000000000061ULL,
    0x00000000000000acULL, 0x0000000400010035ULL, 0x0000000000000016ULL,
    0xffffffff00000006ULL};

/* --- classic BPF interpreter (the cBPF subset the builder emits), with
 * the kernel's out-of-bounds LD semantics: an aborted load returns 0. */
static u32 rpst_ld(const u8* pkt, u32 len, u32 off, u32* a, int* dead) {
  if (off >= len) {
    *dead = 1;
    return 0;
  }
  *a = pkt[off];
  return 1;
}

static u32 rpst_alu(u16 code, u32 a, u32 x, u32 k) {
  switch (code) {
    case 0x0c:
      return a + x;
    case 0x04:
      return a + k;
    case 0x24:
      return a * k;
    case 0x54:
      return a & k;
    case 0x4c:
      return a | x;
    case 0x64:
      return a << k;
    case 0x74:
      return a >> k;
    case 0xa4:
      return a ^ k;
    case 0xac:
      return a ^ x;
    default:
      return a;
  }
}

typedef struct {
  u32 a, x;
  u32 m[16];
  int pc;
  int dead; /* aborted load: kernel returns 0 */
} rpst_vm;

/* One instruction; returns 1 while running, 0 on RET (result in *ret). */
static int rpst_step(
    rpst_vm* v, const u64* prog, const u8* pkt, u32 len, u32* ret) {
  u16 code = (u16)prog[v->pc];
  u8  jt = (u8)(prog[v->pc] >> 16), jf = (u8)(prog[v->pc] >> 24);
  u32 k = (u32)(prog[v->pc] >> 32);
  switch (code) {
    case 0x80:
      v->a = len;
      break;
    case 0x30:
      rpst_ld(pkt, len, k, &v->a, &v->dead);
      break;
    case 0x50:
      rpst_ld(pkt, len, v->x + k, &v->a, &v->dead);
      break;
    case 0x01:
      v->x = k;
      break;
    case 0x60:
      v->a = v->m[k];
      break;
    case 0x61:
      v->x = v->m[k];
      break;
    case 0x02:
      v->m[k] = v->a;
      break;
    case 0x05:
      v->pc += (int)k;
      break;
    case 0x35:
      v->pc += v->a >= k ? jt : jf;
      break;
    case 0x45:
      v->pc += (v->a & k) ? jt : jf;
      break;
    case 0x16:
      *ret = v->a;
      return 0;
    case 0x06:
      *ret = k;
      return 0;
    default:
      v->a = rpst_alu(code, v->a, v->x, k);
      break;
  }
  return 1;
}

/* Run prog over pkt, kernel semantics. */
static u32 rpst_run(const u64* prog, usz n, const u8* pkt, u32 len) {
  rpst_vm v   = {0, 0, {0}, 0, 0};
  u32     ret = 0;
  for (; v.pc < (int)n; v.pc++) {
    if (!rpst_step(&v, prog, pkt, len, &ret)) {
      return ret;
    }
    if (v.dead) {
      return 0;
    }
  }
  return 0;
}

/* splitmix64: deterministic test randomness, no CSPRNG dependency. */
static u64 rpst_rnd_state = 0x243f6a8885a308d3ULL;
static u64 rpst_rnd(void) {
  u64 z = (rpst_rnd_state += 0x9e3779b97f4a7c15ULL);
  z     = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
  z     = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
  return z ^ (z >> 31);
}

/* The built program matches the frozen prototype exactly. */
static void test_rpsteer_prog_build_golden(void) {
  u64 out[RPSTEER_PROG_LEN];
  CHECK(rpsteer_prog_build(out, &rpst_key, 4) == RPSTEER_PROG_LEN);
  for (usz i = 0; i < RPSTEER_PROG_LEN; i++) {
    CHECK(out[i] == rpst_golden[i]);
  }
}

/* A short-header packet with each worker's routing byte (embedded by the
 * production encoder, ncid_route_encode) selects that worker. */
static void test_rpsteer_short_header_each_worker(void) {
  u64 prog[RPSTEER_PROG_LEN];
  rpsteer_prog_build(prog, &rpst_key, 4);
  for (u8 core = 0; core < 4; core++) {
    u8 pkt[12] = {0x41, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    for (usz j = 2; j < 9; j++) {
      pkt[j] = (u8)rpst_rnd();
    }
    CHECK(ncid_route_encode(pkt + 1, 8, core, &rpst_key) == 0);
    CHECK(rpst_run(prog, RPSTEER_PROG_LEN, pkt, sizeof pkt) == core);
  }
}

/* A long header carrying a server-issued DCID (RFC 9000 17.2: DCID at
 * offset 6) selects the issuing worker. */
static void test_rpsteer_long_header_server_cid(void) {
  u64 prog[RPSTEER_PROG_LEN];
  rpsteer_prog_build(prog, &rpst_key, 4);
  for (u8 core = 0; core < 4; core++) {
    u8 pkt[20] = {0xc3, 0, 0, 0, 1, 8, 0, 0, 0, 0,
                  0,    0, 0, 0, 0, 0, 0, 0, 0, 0};
    for (usz j = 7; j < 14; j++) {
      pkt[j] = (u8)rpst_rnd();
    }
    CHECK(ncid_route_encode(pkt + 6, 8, core, &rpst_key) == 0);
    CHECK(rpst_run(prog, RPSTEER_PROG_LEN, pkt, sizeof pkt) == core);
  }
}

/* A DCID this server never issued (its decode lands outside 0..nsock-1)
 * falls back: 0xffffffff, which the kernel maps to its 4-tuple hash. */
static void test_rpsteer_foreign_dcid_falls_back(void) {
  u64 prog[RPSTEER_PROG_LEN];
  u8  pkt[20] = {0xc3, 0, 0, 0, 1, 8, 0, 1, 2, 3, 4, 5, 6, 7, 0, 0, 0, 0};
  rpsteer_prog_build(prog, &rpst_key, 2);
  /* walk cid[0]: decode takes every value as cid[0] varies, so some byte
   * decodes >= 2 (and some < 2 -- also check that side routes) */
  pkt[6] = (u8)(2 ^ ncid_route_mask(pkt + 6, &rpst_key)); /* decode == 2 */
  CHECK(rpst_run(prog, RPSTEER_PROG_LEN, pkt, sizeof pkt) == 0xffffffffu);
  pkt[6] = (u8)(1 ^ ncid_route_mask(pkt + 6, &rpst_key)); /* decode == 1 */
  CHECK(rpst_run(prog, RPSTEER_PROG_LEN, pkt, sizeof pkt) == 1);
}

/* An out-of-range routing byte in a short header falls back too. */
static void test_rpsteer_out_of_range_byte_falls_back(void) {
  u64 prog[RPSTEER_PROG_LEN];
  u8  pkt[12] = {0x41, 0, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0};
  rpsteer_prog_build(prog, &rpst_key, 4);
  CHECK(ncid_route_encode(pkt + 1, 8, 200, &rpst_key) == 0);
  CHECK(rpst_run(prog, RPSTEER_PROG_LEN, pkt, sizeof pkt) == 0xffffffffu);
}

/* Datagrams too short to carry the routed DCID bytes fall back -- via the
 * explicit length guards, never via an aborted load (which would return 0
 * == member 0). */
static void test_rpsteer_truncated_falls_back(void) {
  u64 prog[RPSTEER_PROG_LEN];
  u8  pkt[12] = {0x41, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11};
  rpsteer_prog_build(prog, &rpst_key, 4);
  CHECK(rpst_run(prog, RPSTEER_PROG_LEN, pkt, 5) == 0xffffffffu);
  CHECK(rpst_run(prog, RPSTEER_PROG_LEN, pkt, 0) == 0xffffffffu);
  pkt[0] = 0xc3; /* long header needs 11 bytes */
  CHECK(rpst_run(prog, RPSTEER_PROG_LEN, pkt, 10) == 0xffffffffu);
}

/* Property: for random keys, packets and worker counts, the program's
 * verdict equals the 64-bit reference (ncid_route_decode when in range,
 * fallback otherwise) -- the proof that the 32-bit partial-product
 * recomputation in rpsteer.c equals ncid_route_mask's 64-bit arithmetic. */
static void rpst_one_random_case(void) {
  ncid_route_key k = {{rpst_rnd(), rpst_rnd() | 1, rpst_rnd() | 1}};
  u64            prog[RPSTEER_PROG_LEN];
  u32            nsock = 1 + (u32)(rpst_rnd() % 64);
  u8             pkt[32];
  int            lng = (int)(rpst_rnd() & 1);
  u32 len = lng ? 11 + (u32)(rpst_rnd() % 21) : 6 + (u32)(rpst_rnd() % 26);
  const u8* cid = pkt + (lng ? 6 : 1);
  u8        core;
  u32       want;
  rpsteer_prog_build(prog, &k, nsock);
  for (usz j = 0; j < sizeof pkt; j++) {
    pkt[j] = (u8)rpst_rnd();
  }
  pkt[0] = lng ? (u8)(pkt[0] | 0x80) : (u8)(pkt[0] & 0x7f);
  core   = ncid_route_decode(cid, &k);
  want   = core < nsock ? core : 0xffffffffu;
  CHECK(rpst_run(prog, RPSTEER_PROG_LEN, pkt, len) == want);
}

static void test_rpsteer_decode_matches_reference(void) {
  for (int t = 0; t < 20000; t++) {
    rpst_one_random_case();
  }
}

/* --- real kernel: attach to a 2-socket reuseport group on loopback and
 * prove the same server CID from two different source ports lands on the
 * same (CID-selected) socket -- the 4-tuple changed, the route did not. */

static i64 rpst_bind(sockaddr* sa) {
  i64 fd = wired_udp_socket();
  if (fd < 0) {
    return fd;
  }
  wired_udp_reuseport_enable(fd);
  if (wired_udp_bind(fd, sa) < 0) {
    wired_udp_close(fd);
    return -1;
  }
  return fd;
}

/* Non-blocking: did one datagram arrive on fd? */
static int rpst_got(i64 fd) {
  u8       store[64];
  mmsg_buf b = {{store, sizeof store}, {0}, 0, 0};
  return wired_udp_recvmmsg_nowait(fd, &b, 1) == 1;
}

/* Send pkt from its own throwaway source socket (a fresh source port). */
static void rpst_send_fresh(const sockaddr* dst, const u8* pkt, usz n) {
  i64 cli = wired_udp_socket();
  wired_udp_send(cli, dst, wired_span_of(pkt, n));
  wired_udp_close(cli);
  /* loopback delivery is synchronous by the time sendto returns; a short
   * poll nap keeps this robust on a loaded CI box */
  wired_arch_poll(0, 0, 20);
}

static void rpst_kernel_case(i64 fd0, i64 fd1, const sockaddr* dst) {
  u8 pkt[12] = {0x41, 0, 0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x17, 0, 0, 0};
  CHECK(ncid_route_encode(pkt + 1, 8, 1, &rpst_key) == 0);
  rpst_send_fresh(dst, pkt, sizeof pkt);
  rpst_send_fresh(dst, pkt, sizeof pkt); /* second, different source port */
  CHECK(rpst_got(fd0) == 0);
  CHECK(rpst_got(fd1) == 1);
  CHECK(rpst_got(fd1) == 1);
  /* truncated: falls back to the hash -- delivered somewhere, not dropped,
   * not forced onto member 0 */
  rpst_send_fresh(dst, pkt, 3);
  CHECK(rpst_got(fd0) + rpst_got(fd1) == 1);
}

static void test_rpsteer_kernel_reuseport_group(void) {
  sockaddr sa;
  u64      prog[RPSTEER_PROG_LEN];
  u64      len = sizeof(sockaddr);
  i64      fd0, fd1;
  wired_udp_addr(&sa, 0, (const u8[4]){127, 0, 0, 1});
  fd0 = rpst_bind(&sa);
  if (fd0 < 0) {
    printf("rpsteer: sockets unavailable, kernel reuseport check skipped\n");
    return;
  }
  /* learn the kernel-chosen port, join the group with a second socket */
  CHECK(syscall3(TEST_SYS_getsockname, fd0, (i64)&sa, (i64)&len) == 0);
  fd1 = rpst_bind(&sa);
  CHECK(fd1 >= 0);
  rpsteer_prog_build(prog, &rpst_key, 2);
  CHECK(wired_udp_reuseport_cbpf_attach(fd0, prog, RPSTEER_PROG_LEN) == 0);
  rpst_kernel_case(fd0, fd1, &sa);
  wired_udp_close(fd0);
  wired_udp_close(fd1);
}

void test_rpsteer(void) {
  test_rpsteer_prog_build_golden();
  test_rpsteer_short_header_each_worker();
  test_rpsteer_long_header_server_cid();
  test_rpsteer_foreign_dcid_falls_back();
  test_rpsteer_out_of_range_byte_falls_back();
  test_rpsteer_truncated_falls_back();
  test_rpsteer_decode_matches_reference();
  test_rpsteer_kernel_reuseport_group();
}
