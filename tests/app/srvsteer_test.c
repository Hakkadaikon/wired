#include "app/http3/server/srvsteer/srvsteer.h"

#include "app/http3/server/srvrun/srvrun_impl.h"
#include "test.h"
#include "test_sys.h"
#include "transport/io/socket/io/udp.h"
#include "transport/io/socket/rpsteer/rpsteer.h"

/* A free local UDP port: bind port 0, read the kernel's pick, release it.
 * The tiny reuse race until srvsteer_open rebinds it is acceptable in a
 * test. Returns 0 when sockets are forbidden (sandbox: benign skip). */
static u16 sst_free_port(void) {
  sockaddr sa;
  u64      len = sizeof(sockaddr);
  u16      port;
  i64      fd;
  wired_udp_addr(&sa, 0, (const u8[4]){127, 0, 0, 1});
  fd = wired_udp_socket();
  if (fd < 0) {
    return 0;
  }
  CHECK(wired_udp_bind(fd, &sa) == 0);
  CHECK(syscall3(TEST_SYS_getsockname, fd, (i64)&sa, (i64)&len) == 0);
  port = (u16)((sa.port_be >> 8) | (sa.port_be << 8));
  wired_udp_close(fd);
  return port;
}

/* Refusals: one worker has nothing to steer between, a CID too short to
 * carry the routing byte cannot be steered, and an inactive srvsteer hands
 * out neither fds nor a key nor ownership. */
static void test_srvsteer_refusals(void) {
  CHECK(srvsteer_open(0, 2, 8) == 0); /* port 0: N unrelated ephemerals */
  CHECK(srvsteer_open(4433, 1, 8) == 0);
  CHECK(srvsteer_open(4433, 2, (u8)(NCID_ROUTE_MIN_LEN - 1)) == 0);
  CHECK(srvsteer_open(4433, SRVSTEER_MAX + 1, 8) == 0);
  CHECK(srvsteer_fd(0, 0) == -1);
  CHECK(srvsteer_key() == 0);
  CHECK(srvsteer_owns(3, 0) == 0);
  CHECK(srvsteer_owned(3) == 0);
}

static void sst_check_active(u16 port) {
  CHECK(srvsteer_fd(port, 0) >= 0);
  CHECK(srvsteer_fd(port, 1) >= 0);
  CHECK(srvsteer_fd(port, 0) != srvsteer_fd(port, 1));
  CHECK(srvsteer_fd(port, 2) == -1);
  CHECK(srvsteer_fd(port, -1) == -1);
  /* another port never resolves to this group's sockets */
  CHECK(srvsteer_fd((u16)(port ^ 1), 0) == -1);
  CHECK(srvsteer_key() != 0);
  CHECK(srvsteer_owns(srvsteer_fd(port, 0), 0) == 1);
  CHECK(srvsteer_owns(srvsteer_fd(port, 0), 1) == 0);
  CHECK(srvsteer_owned(srvsteer_fd(port, 1)) == 1);
}

/* RFC 9000 5.2: with steering active, srvrun_issue_cid embeds the issuing
 * worker's index under srvsteer's key when (and only when) the run serves
 * that worker's steering socket -- every issued CID decodes back to the
 * worker (the property the reuseport BPF program routes by). */
static void sst_check_issue_routes(u16 port) {
  conntable  table[WIRED_CONNTABLE_CAP] = {0};
  srvrun_cfg cfg                        = {.core_id = 1, 0, 0, 0, 0};
  cfg.fd                                = srvsteer_fd(port, 1);
  CHECK(srvrun_udp_steer_routing(&cfg) == 1);
  for (int i = 0; i < 32; i++) {
    u8 cid[8];
    CHECK(srvrun_issue_cid(&cfg, table, cid, sizeof cid) == 1);
    CHECK(ncid_route_decode(cid, srvsteer_key()) == 1);
  }
  /* a run on any other socket (or the wrong index) must not embed bytes
   * under this group's key */
  cfg.fd = -1;
  CHECK(srvrun_udp_steer_routing(&cfg) == 0);
  cfg.fd      = srvsteer_fd(port, 1);
  cfg.core_id = 0;
  CHECK(srvrun_udp_steer_routing(&cfg) == 0);
}

/* RFC 9000 5.2: srvrun_listen on the steered port takes the worker's
 * pre-bound socket; any other port (what srvrun_pref_listen passes) opens
 * its own fresh socket instead of hijacking the group's fd. */
static void sst_check_listen(u16 port, u16 other_port) {
  wired_srvrun_opt opt = {0};
  i64              fd;
  opt.core_id      = 0;
  opt.incoming_cpu = -1;
  CHECK(srvrun_listen(port, &opt) == srvsteer_fd(port, 0));
  fd = srvrun_listen(other_port, &opt);
  CHECK(fd >= 0);
  CHECK(srvsteer_owned(fd) == 0);
  wired_udp_close(fd);
}

/* srvrun_pref_listen for a run serving main_fd with the preferred address
 * on pref_port: the parameter stays advertised; returns the pref_fd it set
 * (0 = no second socket) and clears it for the next check. */
static i64 sst_pref_fd(i64 main_fd, u16 pref_port, int core_id) {
  static const u8  v4[4]  = {127, 0, 0, 1};
  static const u8  v6[16] = {0};
  wired_srvboot_id id     = {0};
  wired_srvrun_opt opt    = {0};
  srvrun_cfg       cfg    = {.core_id = core_id, 0, 0, 0, 0};
  i64              fd;
  cfg.fd           = main_fd;
  cfg.env          = &g_srvrun_env;
  opt.core_id      = core_id;
  opt.incoming_cpu = -1;
  id.pref_v4       = v4;
  id.pref_v6       = v6;
  id.pref_v4_port  = pref_port;
  srvrun_pref_listen(&cfg, &id, &opt);
  CHECK(id.pref_v4 != 0);
  fd               = cfg.env->pref_fd;
  cfg.env->pref_fd = 0;
  return fd;
}

/* RFC 9000 9.6.2 / 5.2: on the steered port (word_list defaults both to
 * 4433) no second socket joins the group -- its hash share of first
 * Initials would pin tx_fd to a socket the CID-steered packets never reach
 * -- the main socket serves the preferred address; on another port the
 * listener binds its own socket, never a steered fd. */
static void sst_check_pref_listen(u16 port, u16 other_port) {
  i64 fd;
  CHECK(sst_pref_fd(srvsteer_fd(port, 0), port, 0) == 0);
  /* a run on another socket whose preferred port is the steered one (a
   * thread-mode serve_env beside the group) keeps its own pref socket */
  fd = sst_pref_fd(-1, port, 0);
  CHECK(fd > 0);
  CHECK(srvsteer_owned(fd) == 0);
  wired_udp_close(fd);
  fd = sst_pref_fd(srvsteer_fd(port, 0), other_port, 0);
  CHECK(fd > 0);
  CHECK(srvsteer_owned(fd) == 0);
  wired_udp_close(fd);
}

/* Without steering the same-port preferred address keeps its own second
 * socket, as before steering existed (single worker / steering refused). */
static void sst_check_pref_unsteered(u16 port) {
  wired_srvrun_opt opt = {0};
  i64              main_fd, fd;
  opt.core_id      = -1;
  opt.incoming_cpu = -1;
  main_fd          = srvrun_listen(port, &opt);
  CHECK(main_fd >= 0);
  fd = sst_pref_fd(main_fd, port, -1);
  CHECK(fd > 0);
  CHECK(fd != main_fd);
  wired_udp_close(fd);
  wired_udp_close(main_fd);
}

/* Send pkt from its own throwaway source socket (a fresh source port). */
static void sst_send_fresh(const sockaddr* dst, const u8* pkt, usz n) {
  i64 cli = wired_udp_socket();
  wired_udp_send(cli, dst, wired_span_of(pkt, n));
  wired_udp_close(cli);
  /* loopback delivery is synchronous by the time sendto returns; a short
   * poll nap keeps this robust on a loaded CI box */
  wired_arch_poll(0, 0, 20);
}

/* Non-blocking: did one datagram arrive on fd? */
static int sst_got(i64 fd) {
  u8       store[64];
  mmsg_buf b = {{store, sizeof store}, {0}, 0, 0};
  return wired_udp_recvmmsg_nowait(fd, &b, 1) == 1;
}

/* Send a short-header datagram whose 8-byte DCID decodes to idx under key,
 * from a fresh source port. */
static void sst_send_routed(
    const sockaddr* dst, int idx, const ncid_route_key* key) {
  u8 pkt[12] = {0x41, 0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 1, 2, 3};
  CHECK(ncid_route_encode(pkt + 1, 8, (u8)idx, key) == 0);
  sst_send_fresh(dst, pkt, sizeof pkt);
}

/* RFC 9000 5.2: the production order actually steers through the kernel --
 * attach before the first bind, later sockets joining the group -- so each
 * datagram lands on the socket its DCID encodes, from a fresh source port
 * every time (8 sends mixing both indices: plain hashing passes 1/256).
 * Guards against the attach silently degrading to the hash, which every
 * in-process check would miss. */
static void sst_check_delivery(u16 port) {
  sockaddr dst;
  wired_udp_addr(&dst, port, (const u8[4]){127, 0, 0, 1});
  for (int i = 0; i < 8; i++) {
    int to = i & 1;
    sst_send_routed(&dst, to, srvsteer_key());
    CHECK(sst_got(srvsteer_fd(port, to)) == 1);
    CHECK(sst_got(srvsteer_fd(port, to ^ 1)) == 0);
  }
}

/* A steered fd is owned by srvsteer alone: srvrun_close_listen leaves it
 * open (getsockname still answers), so a thread worker's shutdown never
 * yanks a socket out of the live reuseport group. */
static void sst_check_close_keeps_steered(u16 port) {
  sockaddr   sa;
  u64        len = sizeof(sockaddr);
  srvrun_cfg cfg = {.core_id = 0, 0, 0, 0, 0};
  cfg.fd         = srvsteer_fd(port, 0);
  cfg.env        = &g_srvrun_env;
  srvrun_close_listen(&cfg);
  CHECK(syscall3(TEST_SYS_getsockname, cfg.fd, (i64)&sa, (i64)&len) == 0);
}

/* Open a 2-worker group on a free loopback port; one retry covers another
 * process taking the port between the probe and the bind. Returns the port,
 * or 0 when sockets are unavailable (or open failed: already CHECKed). */
static u16 sst_open_group(void) {
  for (int i = 0; i < 2; i++) {
    u16 port = sst_free_port();
    if (port == 0 || srvsteer_open(port, 2, 8)) {
      return port;
    }
  }
  CHECK(!"srvsteer_open failed on a free port");
  return 0;
}

/* Open a 2-worker steering group on a real loopback port and run every
 * socket-backed check, then close and verify deactivation. */
static void test_srvsteer_open_issue_close(void) {
  u16 port = sst_open_group();
  u16 other_port;
  if (port == 0) {
    printf("srvsteer: sockets unavailable, kernel checks skipped\n");
    return;
  }
  do {
    other_port = sst_free_port();
  } while (other_port == port);
  sst_check_active(port);
  sst_check_issue_routes(port);
  sst_check_delivery(port);
  sst_check_listen(port, other_port);
  sst_check_pref_listen(port, other_port);
  sst_check_delivery(port); /* the pref handling left the mapping intact */
  sst_check_close_keeps_steered(port);
  srvsteer_close();
  CHECK(srvsteer_fd(port, 0) == -1);
  CHECK(srvsteer_key() == 0);
  sst_check_pref_unsteered(port);
}

/* A previous instance's member of port's group: the first one carries a
 * 2-worker selection program under key (attach before bind, as srvsteer). */
static i64 sst_old_member(u16 port, const ncid_route_key* key) {
  u64      prog[RPSTEER_PROG_LEN];
  sockaddr sa;
  i64      fd = wired_udp_socket();
  wired_udp_reuseport_enable(fd);
  if (key) {
    rpsteer_prog_build(prog, key, 2);
    CHECK(wired_udp_reuseport_cbpf_attach(fd, prog, RPSTEER_PROG_LEN) == 0);
  }
  wired_udp_addr(&sa, port, (const u8[4]){0, 0, 0, 0});
  CHECK(wired_udp_bind(fd, &sa) == 0);
  return fd;
}

/* Overlapping restart: the old group still holds the port, so srvsteer_open
 * fails and the workers' own binds join it. Once the old sockets are gone,
 * CIDs the old key decodes in range must still spread by hash -- the old
 * program, which outlives its creator, has been neutralised. 16 sends all
 * reaching one socket by hash: 2^-15. */
static void test_srvsteer_restart_neutralises(void) {
  wired_srvrun_opt opt = {0};
  ncid_route_key   key;
  sockaddr         dst;
  u16              port = sst_free_port();
  i64              old0, old1, w0, w1;
  int              got0 = 0, got1 = 0;
  if (port == 0) {
    return;
  }
  CHECK(ncid_route_keygen(&key));
  old0 = sst_old_member(port, &key);
  old1 = sst_old_member(port, 0);
  CHECK(srvsteer_open(port, 2, 8) == 0); /* EADDRINUSE: a foreign group */
  opt.core_id      = -1;
  opt.incoming_cpu = -1;
  w0               = srvrun_listen(port, &opt);
  w1               = srvrun_listen(port, &opt);
  wired_udp_close(old0);
  wired_udp_close(old1);
  wired_udp_addr(&dst, port, (const u8[4]){127, 0, 0, 1});
  for (int i = 0; i < 16; i++) {
    sst_send_routed(&dst, 1, &key);
    got0 += sst_got(w0);
    got1 += sst_got(w1);
  }
  CHECK(got0 + got1 == 16);
  CHECK(got0 > 0);
  CHECK(got1 > 0);
  wired_udp_close(w0);
  wired_udp_close(w1);
}

void test_srvsteer(void) {
  test_srvsteer_refusals();
  test_srvsteer_open_issue_close();
  test_srvsteer_restart_neutralises();
}
