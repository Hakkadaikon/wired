#include "transport/io/socket/poll/nonblock.h"

i64 poll_set_nonblock(i64 fd) {
  return wired_arch_fcntl(fd, F_SETFL, O_NONBLOCK);
}
