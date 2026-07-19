#include "test.h"

/* The struct is the kernel's sockaddr_in6: 2+2+4+16+4 = 28 bytes, the
 * addrlen every bind/sendto/recvfrom passes. */
static void test_udp_sockaddr_is_sockaddr_in6_sized(void) {
  CHECK(sizeof(quic_sockaddr) == 28);
}

/* A nonzero IPv4 builds the v4-mapped ::ffff:a.b.c.d (RFC 4291 2.5.5.2),
 * big-endian port, zeroed flow/scope. */
static void test_udp_addr_builds_v4_mapped(void) {
  quic_sockaddr sa;
  wired_udp_addr(&sa, 443, (const u8[4]){127, 0, 0, 1});
  CHECK(sa.family == WIRED_AF_INET6);
  /* port 443 = 0x01BB -> network order 0xBB01 on a little-endian host */
  CHECK(sa.port_be == 0xBB01);
  for (usz i = 0; i < 10; i++) CHECK(sa.addr[i] == 0);
  CHECK(sa.addr[10] == 0xff && sa.addr[11] == 0xff);
  CHECK(sa.addr[12] == 127 && sa.addr[13] == 0);
  CHECK(sa.addr[14] == 0 && sa.addr[15] == 1);
  CHECK(sa.flowinfo == 0 && sa.scope_id == 0);
}

/* 0.0.0.0 asks for the dual-stack any-address :: -- a mapped ::ffff:0.0.0.0
 * would bind IPv4-only. */
static void test_udp_addr_all_zero_builds_any(void) {
  quic_sockaddr sa;
  wired_udp_addr(&sa, 443, (const u8[4]){0, 0, 0, 0});
  for (usz i = 0; i < 16; i++) CHECK(sa.addr[i] == 0);
}

/* The v4 accessor reads the mapped bytes back as a host-order u32 -- what
 * the IPv4-only AF_XDP framing path consumes. */
static void test_udp_addr4_be_roundtrip(void) {
  quic_sockaddr sa;
  wired_udp_addr(&sa, 443, (const u8[4]){192, 168, 1, 20});
  CHECK(wired_udp_addr4_be(&sa) == 0xC0A80114);
}

/* The byte-swap is an inverse of a known constant. */
static void test_udp_hton(void) { CHECK(hton16(0x1234) == 0x3412); }

/* getsockopt(2) syscall number (x86_64) -- test-only, the SDK itself never
 * reads options back. */
#define UDPT_SYS_GETSOCKOPT 55

/* The socket comes up AF_INET6 with IPV6_V6ONLY off (dual stack). Sockets
 * may be forbidden in a sandbox; a failed socket() is a benign skip, the
 * same convention udptransport_test uses. */
static void test_udp_socket_dualstack(void) {
  int v6only = 1;
  u64 len    = sizeof(v6only);
  i64 fd     = wired_udp_socket();
  if (fd < 0) return;
  CHECK(
      syscall6(
          UDPT_SYS_GETSOCKOPT, fd, WIRED_IPPROTO_IPV6, WIRED_IPV6_V6ONLY,
          (i64)&v6only, (i64)&len, 0) == 0);
  CHECK(v6only == 0);
  wired_udp_close(fd);
}

/* T-016: cmsg_len 0 must not be treated as a valid entry (would otherwise
 * infinite-loop or read past the header) -- falls back to Not-ECT (0). */
static void test_udp_recvmmsg_malformed_cmsg_len_no_oob_read(void) {
  u8 control[WIRED_GSO_CMSG_SPACE] = {0};
  /* cmsg_len = 0 at offset 0: malformed, must not be walked as an entry. */
  CHECK(cmsg_read_ip_tos(control, sizeof control) == 0);
}

/* T-016 (variant): a cmsg_len claiming more bytes than the buffer holds must
 * not be trusted either -- same OOB-read defense, the overflowing-length
 * half of the boundary. */
static void test_udp_recvmmsg_cmsg_len_overflow_no_oob_read(void) {
  u8 control[WIRED_GSO_CMSG_SPACE] = {0};
  *(u64*)(control + 0)             = 0xffffffffffffffffULL;
  CHECK(cmsg_read_ip_tos(control, sizeof control) == 0);
}

/* T-017: an unrelated cmsg entry (arbitrary level/type) ahead of IP_TOS must
 * be skipped, not mistaken for it or treated as a parse failure. */
static void test_udp_recvmmsg_skips_unrelated_cmsg_to_find_ip_tos(void) {
  u8 control[2 * WIRED_GSO_CMSG_SPACE] = {0};
  /* entry 0: unrelated (level=SOL_SOCKET-ish 1, type=99), 20 bytes payload
   * so CMSG_ALIGN lands the next entry at offset 24 (WIRED_GSO_CMSG_SPACE). */
  *(u64*)(control + 0)  = 16 + 8; /* header + 8-byte payload */
  *(i32*)(control + 8)  = 42;     /* unrelated level */
  *(i32*)(control + 12) = 99;     /* unrelated type */
  /* entry 1 at offset 24: IP_TOS, payload byte = ECT(0) = 2. */
  *(u64*)(control + 24) = 16 + 1;
  *(i32*)(control + 32) = WIRED_IPPROTO_IP;
  *(i32*)(control + 36) = WIRED_IP_TOS;
  control[40]           = 2;
  CHECK(cmsg_read_ip_tos(control, sizeof control) == 2);
}

/* On a dual-stack socket a native-v6 (and on some kernels a v4-mapped)
 * datagram delivers its ECN bits as IPV6_TCLASS instead of IP_TOS -- the
 * walker accepts either level/type pair. */
static void test_udp_cmsg_ecn_ipv6_tclass(void) {
  u8 control[WIRED_GSO_CMSG_SPACE] = {0};
  *(u64*)(control + 0)             = 16 + 1;
  *(i32*)(control + 8)             = 41; /* IPPROTO_IPV6 */
  *(i32*)(control + 12)            = 67; /* IPV6_TCLASS */
  control[16]                      = 3;  /* CE */
  CHECK(cmsg_read_ip_tos(control, sizeof control) == 3);
}

/* T-003: an IP_TOS cmsg whose payload byte is Not-ECT (0x00) reads back 0. */
static void test_udp_recvmmsg_not_ect_reads_as_zero(void) {
  u8 control[WIRED_GSO_CMSG_SPACE] = {0};
  *(u64*)(control + 0)             = 16 + 1;
  *(i32*)(control + 8)             = WIRED_IPPROTO_IP;
  *(i32*)(control + 12)            = WIRED_IP_TOS;
  control[16]                      = 0;
  CHECK(cmsg_read_ip_tos(control, sizeof control) == 0);
}

/* T-005 / T-015: no cmsg at all (controllen 0, as when IP_RECVTOS is off or
 * MSG_CTRUNC truncated the buffer to nothing) falls back to Not-ECT (0). */
static void test_udp_recvmmsg_no_cmsg_defaults_to_zero(void) {
  CHECK(cmsg_read_ip_tos((const u8*)0, 0) == 0);
}

/* T-011: cmsg_read_ip_tos's IP_TOS entry offsets (cmsg_len@0, cmsg_level@8,
 * cmsg_type@12, payload@16) match wired_udp_gso_cmsg_build's manual Linux
 * cmsghdr layout for UDP_SEGMENT -- the same ABI convention read here that
 * that function writes there. */
static void test_udp_recvmmsg_cmsg_layout_matches_kernel_abi(void) {
  u8 control[WIRED_GSO_CMSG_SPACE] = {0};
  /* Written with the identical offsets wired_udp_gso_cmsg_build uses. */
  *(u64*)(control + 0)  = 16 + 1; /* cmsg_len: header(16) + 1-byte payload */
  *(i32*)(control + 8)  = WIRED_IPPROTO_IP;
  *(i32*)(control + 12) = WIRED_IP_TOS;
  control[16]           = 3; /* CE */
  CHECK(cmsg_read_ip_tos(control, sizeof control) == 3);
}

/* T-015: MSG_CTRUNC set on a slot's msg_flags means the cmsg buffer must not
 * be trusted, even though it holds a well-formed-looking IP_TOS entry --
 * recvmmsg_read_ecn falls back to Not-ECT (0) rather than reading it. */
static void test_udp_recvmmsg_msg_ctruncated_falls_back_to_zero(void) {
  u8 control[WIRED_GSO_CMSG_SPACE] = {0};
  *(u64*)(control + 0)             = 16 + 1;
  *(i32*)(control + 8)             = WIRED_IPPROTO_IP;
  *(i32*)(control + 12)            = WIRED_IP_TOS;
  control[16]              = 2; /* ECT(0) -- but MSG_CTRUNC must mask it out */
  quic_mmsghdr  slot       = {0};
  quic_mmsg_buf buf        = {0};
  slot.msg_hdr.msg_control = control;
  slot.msg_hdr.msg_controllen = sizeof control;
  slot.msg_hdr.msg_flags      = WIRED_MSG_CTRUNC;
  recvmmsg_read_ecn(&buf, &slot, 1);
  CHECK(buf.ecn == 0);
}

void test_udp(void) {
  test_udp_sockaddr_is_sockaddr_in6_sized();
  test_udp_addr_builds_v4_mapped();
  test_udp_addr_all_zero_builds_any();
  test_udp_addr4_be_roundtrip();
  test_udp_hton();
  test_udp_socket_dualstack();
  test_udp_cmsg_ecn_ipv6_tclass();
  test_udp_recvmmsg_malformed_cmsg_len_no_oob_read();
  test_udp_recvmmsg_cmsg_len_overflow_no_oob_read();
  test_udp_recvmmsg_skips_unrelated_cmsg_to_find_ip_tos();
  test_udp_recvmmsg_not_ect_reads_as_zero();
  test_udp_recvmmsg_no_cmsg_defaults_to_zero();
  test_udp_recvmmsg_cmsg_layout_matches_kernel_abi();
  test_udp_recvmmsg_msg_ctruncated_falls_back_to_zero();
}
