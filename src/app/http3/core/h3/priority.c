#include "app/http3/core/h3/priority.h"

/* RFC 9218 4.1: defaults are urgency 3, non-incremental. */
void h3_priority_init(h3_priority* p) {
  p->urgency     = H3_URGENCY_DEFAULT;
  p->incremental = 0;
}
