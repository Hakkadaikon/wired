#include "app/http3/server/srvxdpbpf/srvxdpbpf.h"

#include "transport/io/xdp/xdpbpf/xdpbpf.h"

/* Close one fd unconditionally; a negative fd is simply not closed. */
static void srvxdpbpf_close_fd(i64* fd) {
  if (*fd >= 0) {
    wired_arch_close(*fd);
  }
  *fd = -1;
}

/* Reset every fd to -1, draw the CID routing key and create the XSKMAP.
 * Returns 0, or a negative errno. */
static i64 srvxdpbpf_key_and_map(wired_srvxdpbpf* b) {
  b->prog_fd = b->link_fd = b->map_fd = -1;
  if (!ncid_route_keygen(&b->route_key)) {
    return -5; /* -EIO: no key, no obfuscated routing */
  }
  b->map_fd = xdpbpf_map_create(WIRED_SRVXDPBPF_MAP_ENTRIES);
  return b->map_fd < 0 ? b->map_fd : 0;
}

/* srvxdpbpf_key_and_map, then load the redirect-filter program built around
 * the map and key. Returns 0, or the first negative errno. */
static i64 srvxdpbpf_load(wired_srvxdpbpf* b, u16 port) {
  u64 insns[XDPBPF_PROG_LEN];
  i64 r = srvxdpbpf_key_and_map(b);
  if (r < 0) {
    return r;
  }
  xdpbpf_prog_build(insns, (i32)b->map_fd, port, &b->route_key);
  b->prog_fd = xdpbpf_prog_load(insns, XDPBPF_PROG_LEN, wired_mspan_of(0, 0));
  return b->prog_fd < 0 ? b->prog_fd : 0;
}

i64 wired_srvxdpbpf_open(
    wired_srvxdpbpf* b, u32 ifindex, u16 port, u32 attach_flags) {
  i64 r = srvxdpbpf_load(b, port);
  if (r < 0) {
    wired_srvxdpbpf_close(b);
    return r;
  }
  b->link_fd = xdpbpf_link_create(b->prog_fd, ifindex, attach_flags);
  if (b->link_fd < 0) {
    r = b->link_fd;
    wired_srvxdpbpf_close(b);
    return r;
  }
  return 0;
}

i64 wired_srvxdpbpf_register(wired_srvxdpbpf* b, u32 queue_id, u32 xsk_fd) {
  return xdpbpf_map_set(b->map_fd, queue_id, xsk_fd);
}

void wired_srvxdpbpf_close(wired_srvxdpbpf* b) {
  i64* fds[3] = {&b->link_fd, &b->prog_fd, &b->map_fd};
  for (usz i = 0; i < 3; i++) {
    srvxdpbpf_close_fd(fds[i]);
  }
}
