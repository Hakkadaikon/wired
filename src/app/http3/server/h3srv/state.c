#include "app/http3/server/h3srv/state.h"

/* RFC 9204 3.2 */
void wired_h3srv_state_init(wired_h3srv_state* st, u64 max_table_capacity) {
  st->settings_sent            = 0;
  st->peer_control             = 0;
  st->peer_settings            = 0;
  st->request_seen             = 0;
  st->peer_qpack_encoder       = 0;
  st->peer_qpack_decoder       = 0;
  st->qpack_max_table_capacity = max_table_capacity;
  qpack_dyn_init(&st->qdyn, 0);
  /* RFC 9204 3.2.3: the encoder's table starts at capacity 0 and may only
   * grow via Set Dynamic Table Capacity within the PEER's advertised
   * SETTINGS_QPACK_MAX_TABLE_CAPACITY -- never this server's own limit. */
  qpackenc_init(&st->qenc, 0);
}
