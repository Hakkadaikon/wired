#include "transport/version/version/downgrade.h"

/* RFC 9368 6 / RFC 9369 */
int version_downgrade_detected(u32 client_chose, u32 server_reported) {
  return client_chose != server_reported;
}
