#include "tls/keys/keyupdate/oldkey.h"

int oldkey_retain(u64 update_time, u64 now, u64 pto) {
  return now < update_time + 3 * pto;
}

int oldkey_can_discard(u64 update_time, u64 now, u64 pto) {
  return !oldkey_retain(update_time, now, pto);
}
