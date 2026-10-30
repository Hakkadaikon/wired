#include "app/http3/server/srvrun/srvrun_impl.h"

/* dst holding a copy of src (NUL included), or 0 when src is 0; *ok = 0
 * when it does not fit in cap bytes. */
const char* srvrun_own_str(char* dst, usz cap, const char* src, int* ok) {
  usz n;
  if (!src) {
    return 0;
  }
  n = wired_cstr_nlen(src, cap);
  if (n == cap) {
    *ok = 0;
    return 0;
  }
  bytes_memcpy(dst, src, n + 1);
  return dst;
}

void srvrun_own_obs(srvrun_own* o, wired_srvrun_obs* obs, int* ok) {
  obs->qlog_path =
      srvrun_own_str(o->qlog_path, sizeof o->qlog_path, obs->qlog_path, ok);
  obs->keylog_path = srvrun_own_str(
      o->keylog_path, sizeof o->keylog_path, obs->keylog_path, ok);
  obs->cert_path =
      srvrun_own_str(o->cert_path, sizeof o->cert_path, obs->cert_path, ok);
  obs->key_path =
      srvrun_own_str(o->key_path, sizeof o->key_path, obs->key_path, ok);
}
