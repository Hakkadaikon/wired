#include "transport/packet/build/pktbuild/paddingelicit.h"

int pktbuild_padding_elicit_due(u64 last_eliciting_at, u64 now, u64 pto) {
  return now - last_eliciting_at >= pto;
}
