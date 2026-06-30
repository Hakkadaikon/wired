#include "transport/conn/cid/migrate/migrate.h"

void quic_migrate_init(quic_migrate *m, u64 cid) {
  m->handshake_confirmed = 0;
  m->detected            = 0;
  m->challenged          = 0;
  m->validated           = 0;
  m->confirmed           = 0;
  m->cur_cid             = cid;
  m->cc_reset            = 0;
  m->port_only           = 0;
}

void quic_migrate_detect(quic_migrate *m) {
  if (m->handshake_confirmed) m->detected = 1; /* ignored before handshake */
}

void quic_migrate_challenge(quic_migrate *m) {
  if (m->detected) m->challenged = 1; /* challenge follows detection */
}

int quic_migrate_validate(quic_migrate *m) {
  if (!m->detected || !m->challenged) return 0; /* no validation shortcut */
  m->validated = 1;
  return 1;
}

/* Confirmation is allowed only on a validated path switching to a fresh CID. */
static int confirm_ok(const quic_migrate *m, u64 new_cid) {
  return m->validated && new_cid != m->cur_cid;
}

int quic_migrate_confirm(quic_migrate *m, u64 new_cid, int port_only) {
  if (!confirm_ok(m, new_cid)) return 0;
  m->cur_cid   = new_cid; /* switch to the unused CID (old retired) */
  m->confirmed = 1;
  m->port_only = port_only;
  m->cc_reset  = !port_only; /* full migration resets cc/rtt; port-only keeps */
  return 1;
}
