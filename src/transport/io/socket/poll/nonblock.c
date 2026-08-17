#include "transport/io/socket/poll/nonblock.h"

u32 poll_nonblock_flags(u32 flags) { return flags | QUIC_O_NONBLOCK; }

i64 poll_set_nonblock(i64 fd) {
  return wired_arch_fcntl(fd, QUIC_F_SETFL, QUIC_O_NONBLOCK);
}
