/* moqt_chat's rooms in the server (room.h): the flags, the hub hooks and
 * the per-step work. Rooms are on with --public-url (the NIP-98 "u" needs
 * the scheme and authority the hub never sees); without it the hub keeps
 * the single unchecked wired/moqt_chat namespace (chat_authorize_room_ns),
 * which the e2e scenarios that predate rooms run against.
 *
 *   --public-url https://host:4433   rooms on
 *   --nip05 127.0.0.1:4480           nip05d (loopback TCP); none: no room
 *                                    is ever verified
 *   --room-lifetime / --room-alone-timeout / --room-empty-grace <seconds>
 *   --room-allow <domain|pubkey-hex>[,...]  only these may create */

#include "moqt_chat.h"
#include "room.h"

static chatroom_table  g_rooms;
static chatroom_nip05  g_nip05;
static wired_moqt_hub* g_room_hub; /* 0: rooms off */

static void chat_room_close(
    void* ctx, wired_wt_session* s, u32 code, wired_span reason) {
  wired_moqt_close((wired_moqt_hub*)ctx, s, code, reason);
}

/* One decimal digit more of a port; past 65535 it stays out of range. */
static u32 chat_port_step(u32 p, u8 c) {
  int d = ascii_dec(c);
  return d < 0 || p > 65535 ? 1u << 20 : p * 10 + (u32)d;
}

/* s as a port 1..65535, else 0. */
static u16 chat_port_of(const char* s) {
  u32 p = 0;
  for (; *s; s++) {
    p = chat_port_step(p, (u8)*s);
  }
  return p <= 65535 ? (u16)p : 0;
}

/* nip05d must be on this host: 127/8 only (any process here can reach a
 * loopback port, but nothing off the box can). */
static int chat_nip05_ip(const char* ip) {
  return wired_cliargs_ipv4(ip, g_nip05.ip) && g_nip05.port &&
         g_nip05.ip[0] == 127;
}

/* "127.x.x.x:port" into the nip05d client; 0 when malformed. */
static int chat_nip05_addr(const char* v) {
  char ip[16];
  ssz  colon = wired_span_find(wired_span_cstr(v), ':');
  if (colon < 0 || colon >= (ssz)sizeof ip) {
    return 0;
  }
  wired_span_to_cstr(ip, sizeof ip, wired_span_of((const u8*)v, (usz)colon));
  g_nip05.port = chat_port_of(v + colon + 1);
  return chat_nip05_ip(ip);
}

static void chat_nip05_flag(int argc, char** argv) {
  const char* v = wired_cliargs_str(argc, argv, "--nip05", 0);
  if (!v) {
    wired_log_str("moqt rooms: WARNING no --nip05: no room can be verified\n");
    return;
  }
  if (!chat_nip05_addr(v)) {
    wired_die("--nip05: expected 127.x.x.x:port (loopback only)\n");
  }
}

/* A duration flag in seconds (> 0), as milliseconds. */
static u64 chat_room_secs(int argc, char** argv, const char* flag, u64 def_ms) {
  i64 v = wired_cliargs_int(argc, argv, flag, (i64)(def_ms / 1000));
  if (v <= 0) {
    wired_die("--room-*: expected a positive number of seconds\n");
  }
  return (u64)v * 1000;
}

static void chat_room_flags(int argc, char** argv) {
  g_rooms.lifetime_ms =
      chat_room_secs(argc, argv, "--room-lifetime", g_rooms.lifetime_ms);
  g_rooms.alone_ms =
      chat_room_secs(argc, argv, "--room-alone-timeout", g_rooms.alone_ms);
  g_rooms.empty_ms =
      chat_room_secs(argc, argv, "--room-empty-grace", g_rooms.empty_ms);
  g_rooms.allow = wired_cliargs_str(argc, argv, "--room-allow", 0);
  chat_nip05_flag(argc, argv);
}

/* Admission, the three authorizers, and the tap on wired/moqt_chat for
 * the host's 30313 (an event fits the table's parse buffer). */
static void chat_room_hooks(wired_moqt_hub* hub) {
  static u8 prefix[32];
  moqctl_ns ns  = {0};
  usz       off = 0;
  ns.fields[0]  = wired_span_cstr("wired");
  ns.fields[1]  = wired_span_cstr("moqt_chat");
  ns.n          = 2;
  moqctl_ns_put(wired_mspan_of(prefix, sizeof prefix), &off, &ns);
  hub->admit               = chatroom_admit;
  hub->admit_ctx           = &g_rooms;
  hub->authorize_namespace = chatroom_authorize_ns;
  hub->authorize_ns_ctx    = &g_rooms;
  hub->authorize_publish   = chatroom_authorize_pub;
  hub->authorize_pub_ctx   = &g_rooms;
  hub->authorize_subscribe = chatroom_authorize_sub;
  hub->authorize_ctx       = &g_rooms;
  hub->tap                 = chatroom_tap;
  hub->tap_ctx             = &g_rooms;
  hub->tap_prefix          = wired_span_of(prefix, off);
  hub->tap_max             = sizeof g_rooms.buf;
}

void chat_rooms_setup(wired_moqt_hub* hub, int argc, char** argv) {
  const char* url = wired_cliargs_str(argc, argv, "--public-url", 0);
  if (!url) {
    wired_log_str("moqt rooms: OFF (unchecked namespace)\n");
    return;
  }
  chatroom_init(&g_rooms);
  chatroom_nip05_init(&g_nip05);
  g_rooms.public_url = url;
  g_rooms.log        = 1;
  g_rooms.close      = chat_room_close;
  g_rooms.close_ctx  = hub;
  g_rooms.ask        = chatroom_nip05_ask;
  g_rooms.ask_ctx    = &g_nip05;
  chat_room_flags(argc, argv);
  chat_room_hooks(hub);
  g_room_hub = hub;
  wired_log_str("moqt rooms: on\n");
}

void chat_rooms_opened(wired_wt_session* s, wired_span path) {
  if (g_room_hub) {
    chatroom_opened(&g_rooms, s, path);
  }
}

void chat_rooms_closed(wired_wt_session* s) {
  if (g_room_hub) {
    chatroom_closed(&g_rooms, s);
  }
}

void chat_rooms_step(u64 now_ms) {
  if (!g_room_hub) {
    return;
  }
  chatroom_tick(&g_rooms, now_ms, wired_clock_epoch_secs());
  chatroom_nip05_poll(&g_nip05, &g_rooms);
}

static void chat_room_goaway(const chatroom* r, const char* uri, u64 timeout) {
  static char out[WIRED_MOQTRUN_GOAWAY_URI_MAX + 1];
  for (usz k = 0; k < r->n; k++) {
    usz n = chatroom_goaway_uri(&g_rooms, r->m[k].s, uri, out, sizeof out);
    wired_moqt_goaway_session(
        g_room_hub, r->m[k].s, wired_span_of((const u8*)out, n), timeout);
  }
}

static int chat_rooms_redirect(const char* uri) { return g_room_hub && *uri; }

/* --goaway-uri keeps each member's ?room=&host= (the frontend reconnects
 * to the URI as given); an empty URI already means "the same URL". */
void chat_rooms_goaway(const char* uri, u64 timeout_ms) {
  if (!chat_rooms_redirect(uri)) {
    return;
  }
  for (usz i = 0; i < WIRED_MOQT_CHAT_MAX_ROOMS; i++) {
    chat_room_goaway(&g_rooms.room[i], uri, timeout_ms);
  }
}

/* " <token>=<count>" for reason r ("setup-timeout" has no token). */
static usz chat_room_count(char* line, usz cap, usz n, chatroom_reason r) {
  char       num[24];
  wired_span tok = chatroom_reason_token(r);
  n              = wired_cstr_append(line, cap, n, wired_span_cstr(" "));
  n              = wired_cstr_append(
      line, cap, n, tok.n ? tok : wired_span_cstr("setup-timeout"));
  wired_snprintf(num, sizeof num, "=%llu", (u64)g_rooms.refused[r]);
  return wired_cstr_append(line, cap, n, wired_span_cstr(num));
}

/* The admission counters: admitted, then refusals per reason token. */
void chat_rooms_log(void) {
  char line[512];
  usz  n;
  if (!g_room_hub) {
    return;
  }
  wired_snprintf(
      line, sizeof line, "moqt rooms: admitted=%llu refused",
      (u64)g_rooms.refused[CHATROOM_R_NONE]);
  n = wired_cstr_len(line);
  for (usz r = 1; r < CHATROOM_R_N; r++) {
    n = chat_room_count(line, sizeof line, n, (chatroom_reason)r);
  }
  wired_cstr_append(line, sizeof line, n, wired_span_cstr("\n"));
  wired_log_str(line);
}
