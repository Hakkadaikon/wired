#include "transport/conn/loop/manage/observable.h"

/* Fields exposed only by a long header (RFC 9312 3): version and both CIDs
 * are plaintext in the long header that carries them. */
static int long_only_field(int field_id) {
  return field_id == OBS_VERSION || field_id == OBS_SCID ||
         field_id == OBS_DCID;
}

int observable_field(int field_id, int is_long) {
  if (field_id == OBS_SPIN) return !is_long; /* short header only */
  if (is_long) return long_only_field(field_id);
  return field_id == OBS_DCID; /* short: only the DCID is plaintext */
}
