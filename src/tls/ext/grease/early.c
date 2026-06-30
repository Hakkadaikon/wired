#include "tls/ext/grease/early.h"

int quic_greasebit_client_early_ok(int remembered_advertised) {
  return remembered_advertised != 0; /* RFC 9287 3.1 */
}

int quic_greasebit_server_ok(int client_tp_processed, int we_advertised) {
  return client_tp_processed != 0 && we_advertised != 0; /* RFC 9287 3.1 */
}
