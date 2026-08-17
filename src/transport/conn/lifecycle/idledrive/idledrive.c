#include "transport/conn/lifecycle/idledrive/idledrive.h"

/* RFC 9000 10.1 */
void idledrive_init(idledrive* s, u64 idle_timeout) {
  s->idle_timeout  = idle_timeout;
  s->last_activity = 0;
}

/* RFC 9000 10.1 */
void idledrive_on_activity(idledrive* s, u64 now) { s->last_activity = now; }

/* RFC 9000 10.1 */
int idledrive_expired(const idledrive* s, u64 now) {
  return s->idle_timeout != 0 && now - s->last_activity >= s->idle_timeout;
}
