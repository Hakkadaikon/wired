#include "app/http3/server/srvsteer/srvsteer.h"

#include "app/http3/server/srvsteer/srvsteer_check.h"
#include "transport/io/socket/io/udp.h"
#include "transport/io/socket/rpsteer/rpsteer.h"

/* The one steering group this process serves (see srvsteer.h on why a
 * process global is the right scope for both the fork and threads driver). */
typedef struct {
  ncid_route_key key;
  i64            fds[SRVSTEER_MAX];
  u16            port; /* the port the group was opened for */
  int            n;    /* 0 = inactive */
} srvsteer_state;

static srvsteer_state g_srvsteer;

/* At least two workers to steer between, within the fd table, and a CID
 * long enough to carry the routing byte. */
static int srvsteer_size_ok(int n, u8 scid_len) {
  return n >= 2 && n <= SRVSTEER_MAX && scid_len >= NCID_ROUTE_MIN_LEN;
}

/* Steering applies: a real port on top of the size checks -- port 0 would
 * bind N unrelated ephemeral ports, never one reuseport group. */
static int srvsteer_want(u16 port, int n, u8 scid_len) {
  return port != 0 && srvsteer_size_ok(n, scid_len);
}

/* Attach the selection program to fd (before fd's bind: the whole group
 * inherits it, so no datagram is ever dispatched un-programmed). n 0
 * selects nobody: every datagram takes the kernel hash fallback. */
static int srvsteer_attach(i64 fd, int n) {
  u64 prog[RPSTEER_PROG_LEN];
  usz len = rpsteer_prog_build(prog, &g_srvsteer.key, (u32)n);
  return wired_udp_reuseport_cbpf_attach(fd, prog, (u16)len) == 0;
}

/* Bind fd to port, closing it on failure. Returns fd or -1. */
static i64 srvsteer_finish_bind(i64 fd, u16 port) {
  sockaddr sa;
  wired_udp_addr(&sa, port, (const u8[4]){0, 0, 0, 0});
  if (wired_udp_bind(fd, &sa) < 0) {
    wired_udp_close(fd);
    return -1;
  }
  return fd;
}

/* Socket 0 carries the group's program: reuseport -> attach -> bind, in
 * that order (SO_ATTACH_REUSEPORT_CBPF accepts an unbound socket and the
 * group formed by the bind inherits the program; verified on Linux 6.8). */
static i64 srvsteer_bind_first(u16 port, int n) {
  i64 fd = wired_udp_socket();
  if (fd < 0) {
    return fd;
  }
  wired_udp_reuseport_enable(fd);
  if (!srvsteer_attach(fd, n)) {
    wired_udp_close(fd);
    return -1;
  }
  return srvsteer_finish_bind(fd, port);
}

/* One more SO_REUSEPORT socket joining the group (reuseport BEFORE bind,
 * or the sockets would not form one group). Returns the fd or negative. */
static i64 srvsteer_bind_one(u16 port) {
  i64 fd = wired_udp_socket();
  if (fd < 0) {
    return fd;
  }
  wired_udp_reuseport_enable(fd);
  return srvsteer_finish_bind(fd, port);
}

static void srvsteer_close_upto(int n) {
  for (int i = 0; i < n; i++) {
    wired_udp_close(g_srvsteer.fds[i]);
  }
}

static int srvsteer_bind_rest(u16 port, int n) {
  for (int i = 1; i < n; i++) {
    g_srvsteer.fds[i] = srvsteer_bind_one(port);
    if (g_srvsteer.fds[i] < 0) {
      srvsteer_close_upto(i);
      return 0;
    }
  }
  return 1;
}

/* Bind all n sockets in worker order (the order IS the group index the BPF
 * program selects by). On failure closes what was bound and returns 0. */
static int srvsteer_bind_all(u16 port, int n) {
  g_srvsteer.fds[0] = srvsteer_bind_first(port, n);
  return g_srvsteer.fds[0] >= 0 && srvsteer_bind_rest(port, n);
}

static int srvsteer_setup(u16 port, int n) {
  return ncid_route_keygen(&g_srvsteer.key) && srvsteer_bind_all(port, n);
}

/* Open failed, so the workers will bind plain reuseport sockets -- and if a
 * previous instance's group still holds the port (an overlapping restart:
 * the attach-before-bind above fails EADDRINUSE), they join THAT group,
 * whose selection program outlives its creator and still decodes under the
 * old key. Replace it through a short-lived member with an nsock-0 program
 * (every decode is out of range: always the kernel hash fallback), so the
 * new workers' random CIDs are never pinned to an index. With no group on
 * the port the member forms one alone and it vanishes with the close. */
static void srvsteer_neutralise(u16 port) {
  i64 fd = srvsteer_bind_one(port);
  if (fd >= 0) {
    srvsteer_attach(fd, 0);
    wired_udp_close(fd);
  }
}

int srvsteer_open(u16 port, int n, u8 scid_len) {
  if (!srvsteer_want(port, n, scid_len)) {
    return 0;
  }
  g_srvsteer.port = port;
  g_srvsteer.n    = 0;
  if (srvsteer_setup(port, n)) {
    g_srvsteer.n = n;
    return 1;
  }
  srvsteer_neutralise(port);
  return 0;
}

/* The lookup misses: wrong port (another listener in this process, e.g.
 * the preferred-address socket, must bind its own), or idx outside the
 * open group (inactive included: n == 0 rejects every idx). */
static int srvsteer_mismatch(u16 port, int idx) {
  return port != g_srvsteer.port || idx < 0 || idx >= g_srvsteer.n;
}

i64 srvsteer_fd(u16 port, int idx) {
  if (srvsteer_mismatch(port, idx)) {
    return -1;
  }
  return g_srvsteer.fds[idx];
}

int srvsteer_owns(i64 fd, int idx) {
  if (idx < 0 || idx >= g_srvsteer.n) {
    return 0;
  }
  return g_srvsteer.fds[idx] == fd;
}

int srvsteer_owned(i64 fd) {
  for (int i = 0; i < g_srvsteer.n; i++) {
    if (g_srvsteer.fds[i] == fd) {
      return 1;
    }
  }
  return 0;
}

const ncid_route_key* srvsteer_key(void) {
  return g_srvsteer.n ? &g_srvsteer.key : 0;
}

void srvsteer_close(void) {
  srvsteer_close_upto(g_srvsteer.n);
  g_srvsteer.n = 0;
}
