/* moqt_chat rooms: the nip05d client (examples/moqt_chat/nip05d/README.md
 * section 2). One loopback TCP connection, opened on demand, never
 * blocking: requests "check <name@domain> <pubkey>\n" queue in out, and
 * nip05d answers each in order, so each whole line is the verdict of the
 * oldest outstanding (slot, nonce). Only "ok" verifies; "fail" and
 * "unknown" end the room. nip05d echoes neither the name nor the key in its
 * reply, so lines match requests by order only (the protocol is left as
 * is); the (slot, nonce) still keeps a verdict to its room instance. A
 * broken connection drops every outstanding
 * request: those rooms reach the 3 s timeout and end nip05-unverified. */

#include "common/arch/sysops.h"
#include "room.h"
#include "transport/io/socket/io/udp.h"

#define CHATROOM_SOCK_STREAM 1
#define CHATROOM_SOCK_NONBLOCK 0x800
#define CHATROOM_MSG_NOSIGNAL 0x4000 /* a reset peer must not SIGPIPE us */
#define CHATROOM_EAGAIN 11
#define CHATROOM_EINPROGRESS 115

/* The kernel's sockaddr_in. */
typedef struct {
  u16 family;
  u16 port_be;
  u8  addr[4];
  u8  zero[8];
} chatroom_sin;

void chatroom_nip05_init(chatroom_nip05* c) {
  bytes_memset(c, 0, sizeof *c);
  c->fd = -1;
}

void chatroom_nip05_ask(
    void* ctx, usz slot, u64 nonce, wired_span nip05, wired_span pubkey) {
  chatroom_nip05* c = (chatroom_nip05*)ctx;
  char            line[CHATROOM_ASK_LINE];
  usz             n;
  if (c->q_n >= CHATROOM_ASK_MAX) {
    return; /* the room times out */
  }
  n = wired_cstr_append(line, sizeof line, 0, wired_span_cstr("check "));
  n = wired_cstr_append(line, sizeof line, n, nip05);
  n = wired_cstr_append(line, sizeof line, n, wired_span_cstr(" "));
  n = wired_cstr_append(line, sizeof line, n, pubkey);
  n = wired_cstr_append(line, sizeof line, n, wired_span_cstr("\n"));
  bytes_memcpy(c->out + c->out_n, line, n);
  c->out_n += n;
  c->q[c->q_n++] = (chatroom_asked){slot, nonce};
}

static void chatroom_nip05_line(chatroom_nip05* c, chatroom_table* t) {
  int            ok = wired_span_eq_cstr(wired_span_of(c->in, c->in_n), "ok");
  chatroom_asked a  = c->q[0];
  c->in_n           = 0;
  if (!c->q_n) {
    return;
  }
  c->q_n--;
  bytes_move_down(c->q, c->q + 1, c->q_n * sizeof c->q[0]);
  chatroom_verdict(t, a.slot, a.nonce, ok);
}

static void chatroom_nip05_byte(chatroom_nip05* c, chatroom_table* t, u8 b) {
  if (b == '\n') {
    chatroom_nip05_line(c, t);
    return;
  }
  if (c->in_n < sizeof c->in) {
    c->in[c->in_n++] = b;
  }
}

void chatroom_nip05_feed(
    chatroom_nip05* c, chatroom_table* t, const u8* p, usz n) {
  for (usz i = 0; i < n; i++) {
    chatroom_nip05_byte(c, t, p[i]);
  }
}

static int chatroom_nip05_transient(i64 err) {
  return err == -CHATROOM_EAGAIN || err == -CHATROOM_EINPROGRESS;
}

/* A syscall result: success (>= 0), still connecting or nothing yet keeps
 * the connection; any error (EOF is passed as one) drops it with every
 * outstanding request. */
static void chatroom_nip05_fail(chatroom_nip05* c, i64 err) {
  if (err >= 0 || chatroom_nip05_transient(err)) {
    return;
  }
  wired_arch_close(c->fd);
  c->fd    = -1;
  c->out_n = 0;
  c->in_n  = 0;
  c->q_n   = 0;
}

static void chatroom_nip05_connect(chatroom_nip05* c) {
  chatroom_sin sa = {
      WIRED_AF_INET, (u16)((c->port >> 8) | (c->port << 8)), {0}, {0}};
  bytes_memcpy(sa.addr, c->ip, 4);
  c->fd = wired_arch_socket(
      WIRED_AF_INET, CHATROOM_SOCK_STREAM | CHATROOM_SOCK_NONBLOCK, 0);
  if (c->fd >= 0) {
    chatroom_nip05_fail(c, wired_arch_connect(c->fd, &sa, sizeof sa));
  }
}

/* A syscall result as an error: EOF (0) is one too. */
static i64 chatroom_nip05_err(i64 n) { return n ? n : -1; }

static void chatroom_nip05_send(chatroom_nip05* c) {
  i64 n;
  if (!c->out_n) {
    return;
  }
  n = wired_arch_sendto(c->fd, c->out, c->out_n, CHATROOM_MSG_NOSIGNAL, 0, 0);
  if (n <= 0) {
    chatroom_nip05_fail(c, chatroom_nip05_err(n));
    return;
  }
  c->out_n -= (usz)n;
  bytes_move_down(c->out, c->out + n, c->out_n);
}

static void chatroom_nip05_recv(chatroom_nip05* c, chatroom_table* t) {
  /* zeroed: the analyzer cannot see read(2) fill it */
  u8  buf[CHATROOM_ASK_LINE] = {0};
  i64 n                      = wired_arch_read(c->fd, buf, sizeof buf);
  if (n <= 0) {
    chatroom_nip05_fail(c, chatroom_nip05_err(n));
    return;
  }
  chatroom_nip05_feed(c, t, buf, (usz)n);
}

static void chatroom_nip05_io(chatroom_nip05* c, chatroom_table* t) {
  if (c->fd < 0) {
    return;
  }
  chatroom_nip05_send(c);
  if (c->fd >= 0) {
    chatroom_nip05_recv(c, t);
  }
}

/* Work to do: a resolver is set and a request waits or a connection is
 * open (an idle one is read so its EOF is noticed). */
static int chatroom_nip05_busy(const chatroom_nip05* c) {
  return c->port && (c->q_n || c->fd >= 0);
}

void chatroom_nip05_poll(chatroom_nip05* c, chatroom_table* t) {
  if (!chatroom_nip05_busy(c)) {
    return;
  }
  if (c->fd < 0) {
    chatroom_nip05_connect(c);
  }
  chatroom_nip05_io(c, t);
}
