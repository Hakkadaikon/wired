#include "transport/io/socket/poll/nonblock.h"

#define SYS_fcntl 72 /* x86_64 fcntl */

u32 quic_poll_nonblock_flags(u32 flags) { return flags | QUIC_O_NONBLOCK; }

i64 quic_poll_set_nonblock(i64 fd) {
  return syscall3(SYS_fcntl, fd, QUIC_F_SETFL, QUIC_O_NONBLOCK);
}
