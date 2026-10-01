#define WIRED_MAIN /* this file provides _start, memcpy and memset */
#include "wired.h"

int wired_main(int argc, char** argv) {
  (void)argc;
  (void)argv;
  wired_log_str("hello\n"); /* stderr */
  return 0;
}
