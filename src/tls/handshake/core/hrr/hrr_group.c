#include "tls/handshake/core/hrr/hrr_group.h"

#include "tls/handshake/core/tls/ext_block.h"
#include "tls/handshake/core/tls/handshake.h"

static u16 hrr_rd16(const u8* p) { return (u16)((p[0] << 8) | p[1]); }

/* Offset of the extension block within the body: legacy_version(2) random(32)
 * session_id(1+sid_len) cipher(2) compression(1). Returns 0 if it runs past
 * body_len. */
static usz hrr_ext_off(const u8* body, usz body_len) {
  usz sid_len, off;
  if (body_len < 35) return 0;
  sid_len = body[34];
  off     = 35 + sid_len + 3;           /* + cipher(2) + compression(1) */
  return off + 2 <= body_len ? off : 0; /* room for ext block length */
}

/* Scan extensions [ext, ext+total) for key_share; on a match write its first
 * two bytes (selected_group) and return 1, else 0. */
/* Classify the extension at `e` (with `room` bytes available): return its
 * total size (header + ext_data) advancing the scan, 0 if it overruns. When it
 * is a key_share carrying the selected_group, write the group to *group. */
/* A key_share extension carrying at least the 2-byte selected_group. */
static int hrr_is_key_share(const u8* e, usz el) {
  return hrr_rd16(e) == QUIC_EXT_KEY_SHARE && el >= 2;
}

/* Scan progress: the selected_group once found, and whether it has been. */
typedef struct {
  u16 group;
  int found;
} hrr_scan_state;

static usz hrr_step(const u8* e, usz room, hrr_scan_state* st) {
  usz el = hrr_rd16(e + 2);
  if (4 + el > room) return 0;
  st->found = hrr_is_key_share(e, el);
  if (st->found) st->group = hrr_rd16(e + 4);
  return 4 + el;
}

static int hrr_scan_more(usz i, usz total, int found) {
  return i + 4 <= total && !found;
}

static int hrr_scan_key_share(const u8* ext, usz total, u16* group) {
  usz            i  = 0;
  hrr_scan_state st = {0, 0};
  while (hrr_scan_more(i, total, st.found)) {
    usz step = hrr_step(ext + i, total - i, &st);
    if (step == 0) return 0;
    i += step;
  }
  *group = st.group;
  return st.found;
}

/* Locate the extension block of a parsed ServerHello body; return its byte
 * offset within the body (>0) and set *total to the block length, or 0. */
static usz hrr_locate_exts(const u8* body, usz body_len, usz* total) {
  usz eoff = hrr_ext_off(body, body_len);
  if (eoff == 0) return 0;
  *total = hrr_rd16(body + eoff);
  return eoff + 2 + *total <= body_len ? eoff : 0;
}

static int hrr_is_server_hello(usz hdr, u8 type) {
  return hdr != 0 && type == QUIC_HS_SERVER_HELLO;
}

int quic_hrr_selected_group(const u8* hrr_msg, usz len, u16* group) {
  u8  type;
  usz body_len, total, eoff;
  usz hdr = quic_hs_parse(quic_span_of(hrr_msg, len), &type, &body_len);
  if (!hrr_is_server_hello(hdr, type)) return 0;
  eoff = hrr_locate_exts(hrr_msg + hdr, body_len, &total);
  if (eoff == 0) return 0;
  return hrr_scan_key_share(hrr_msg + hdr + eoff + 2, total, group);
}
