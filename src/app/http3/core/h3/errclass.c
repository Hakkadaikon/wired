#include "app/http3/core/h3/errclass.h"

#include "app/http3/core/h3/frame.h"

u64 h3_error_send_value(u64 code, u64 grease_id) {
  if (code != H3_NO_ERROR) {
    return code;
  }
  return grease_id ? grease_id : code;
}
