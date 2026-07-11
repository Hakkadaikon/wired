#include "app/http3/server/srvxdpbpf/srvxdpbpf.h"

#include "transport/io/xdp/xdpbpf/xdpbpf.h"

/* Close one fd unconditionally; a negative fd is simply not closed. */
static void srvxdpbpf_close_fd(i64* fd) {
  if (*fd >= 0) syscall1(SYS_close, *fd);
  *fd = -1;
}

/* Reset every fd to -1, then create the XSKMAP and load the redirect-filter
 * program built around it. Returns 0, or the first negative errno. */
static i64 srvxdpbpf_load(wired_srvxdpbpf* b, u16 port) {
  u64 insns[QUIC_XDPBPF_PROG_LEN];
  b->prog_fd = b->link_fd = -1;
  b->map_fd               = quic_xdpbpf_map_create(WIRED_SRVXDPBPF_MAP_ENTRIES);
  if (b->map_fd < 0) return b->map_fd;
  quic_xdpbpf_prog_build(insns, (i32)b->map_fd, port);
  b->prog_fd =
      quic_xdpbpf_prog_load(insns, QUIC_XDPBPF_PROG_LEN, quic_mspan_of(0, 0));
  return b->prog_fd < 0 ? b->prog_fd : 0;
}

i64 wired_srvxdpbpf_open(
    wired_srvxdpbpf* b, u32 ifindex, u16 port, u32 attach_flags) {
  i64 r = srvxdpbpf_load(b, port);
  if (r < 0) {
    wired_srvxdpbpf_close(b);
    return r;
  }
  b->link_fd = quic_xdpbpf_link_create(b->prog_fd, ifindex, attach_flags);
  if (b->link_fd < 0) {
    r = b->link_fd;
    wired_srvxdpbpf_close(b);
    return r;
  }
  return 0;
}

i64 wired_srvxdpbpf_register(wired_srvxdpbpf* b, u32 queue_id, u32 xsk_fd) {
  return quic_xdpbpf_map_set(b->map_fd, queue_id, xsk_fd);
}

void wired_srvxdpbpf_close(wired_srvxdpbpf* b) {
  i64* fds[3] = {&b->link_fd, &b->prog_fd, &b->map_fd};
  for (usz i = 0; i < 3; i++) srvxdpbpf_close_fd(fds[i]);
}
