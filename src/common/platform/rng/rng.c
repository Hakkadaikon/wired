#include "common/platform/rng/rng.h"

/* getrandom returning <= 0 means no progress: EINTR/EAGAIN or a hard error.
   Either way the caller cannot make progress this round, so treat as failure.
 */
static int rng_no_progress(i64 ret) { return ret <= 0; }

int quic_rng_bytes(u8* buf, usz len) {
  usz done = 0;
  while (done < len) {
    i64 ret = syscall3(SYS_getrandom, buf + done, len - done, 0);
    if (rng_no_progress(ret)) return 0;
    done += (usz)ret;
  }
  return 1;
}
