#include "common/platform/exit/exit.h"

#include "common/platform/debug/debug.h"

void wired_die(const char* msg) {
  wired_log_str(msg);
  wired_arch_exit(1);
  __builtin_unreachable();
}
