#include "test.h"

/* Old-shape conveniences over the appdata param objects. Defined here (the
 * first appdata test in tests/run.c order) and shared by the app/tls appdata
 * tests included after this file in the unity test build. */
static int appdata_frame_flat(
    u64       sid,
    u64       off,
    const u8* d,
    usz       n,
    int       fin,
    u8*       out,
    usz       cap,
    usz*      out_len) {
  quic_stream_frame f  = {sid, off, n, d, (u8)(fin ? 1 : 0)};
  quic_obuf         ob = quic_obuf_of(out, cap);
  if (!quic_appdata_stream_frame(&f, &ob)) return 0;
  *out_len = ob.len;
  return 1;
}

static int appdata_send_flat(
    const quic_initial_keys* k,
    const quic_aes128*       hp,
    const u8*                dcid,
    u8                       dcid_len,
    u64                      pn,
    u64                      sid,
    const u8*                data,
    usz                      len,
    int                      fin,
    u8*                      out,
    usz                      cap,
    usz*                     out_len) {
  quic_protect_keys pk = {k, hp};
  quic_appdata_tx   tx = {{dcid, dcid_len}, pn, sid, {data, len}, fin};
  quic_obuf         ob = quic_obuf_of(out, cap);
  if (!quic_appdata_send(&pk, &tx, &ob)) return 0;
  *out_len = ob.len;
  return 1;
}

static int appdata_recv_flat(
    const quic_initial_keys* k,
    const quic_aes128*       hp,
    u8*                      pkt,
    usz                      len,
    u8                       dcid_len,
    u64*                     sid,
    u64*                     off,
    const u8**               data,
    usz*                     dlen,
    int*                     fin) {
  quic_protect_keys pk = {k, hp};
  quic_appdata_pkt  ap = {{pkt, len}, dcid_len};
  quic_stream_frame f;
  if (!quic_appdata_recv(&pk, &ap, &f)) return 0;
  *sid  = f.stream_id;
  *off  = f.offset;
  *data = f.data;
  *dlen = (usz)f.length;
  *fin  = f.fin;
  return 1;
}

/* RFC 9000 19.8: a STREAM frame with offset 0 and no fin sets only the LEN
 * bit; the type byte is 0x0a (0x08 | LEN). It round-trips via get_stream. */
static void test_stream_frame_basic(void) {
  const u8 data[] = {'h', 'i'};
  u8       out[32];
  usz      olen = 0;
  CHECK(
      appdata_frame_flat(4, 0, data, sizeof(data), 0, out, sizeof(out), &olen));
  CHECK(out[0] == (QUIC_FRAME_STREAM_BASE | QUIC_STREAM_LEN));

  quic_stream_frame f;
  CHECK(quic_frame_get_stream(out, olen, &f) == olen);
  CHECK(f.stream_id == 4);
  CHECK(f.offset == 0);
  CHECK(f.length == sizeof(data));
  CHECK(f.fin == 0);
  CHECK(f.data[0] == 'h' && f.data[1] == 'i');
}

/* RFC 9000 19.8: nonzero offset sets OFF, fin sets FIN; both reflected in the
 * type byte and recovered by the decoder. */
static void test_stream_frame_off_fin(void) {
  const u8 data[] = {'x'};
  u8       out[32];
  usz      olen = 0;
  CHECK(appdata_frame_flat(7, 100, data, 1, 1, out, sizeof(out), &olen));
  CHECK(
      out[0] == (QUIC_FRAME_STREAM_BASE | QUIC_STREAM_OFF | QUIC_STREAM_LEN |
                 QUIC_STREAM_FIN));

  quic_stream_frame f;
  CHECK(quic_frame_get_stream(out, olen, &f) == olen);
  CHECK(f.stream_id == 7);
  CHECK(f.offset == 100);
  CHECK(f.fin == 1);
}

/* RFC 9000 19.8: OFF without FIN sets type 0x0e (OFF|LEN, FIN clear); the
 * three bits are independent. */
static void test_stream_frame_off_nofin(void) {
  const u8 data[] = {'q'};
  u8       out[32];
  usz      olen = 0;
  CHECK(appdata_frame_flat(3, 5, data, 1, 0, out, sizeof(out), &olen));
  CHECK(out[0] == (QUIC_FRAME_STREAM_BASE | QUIC_STREAM_OFF | QUIC_STREAM_LEN));
  CHECK((out[0] & QUIC_STREAM_FIN) == 0);

  quic_stream_frame f;
  CHECK(quic_frame_get_stream(out, olen, &f) == olen);
  CHECK(f.offset == 5);
  CHECK(f.fin == 0);
}

/* RFC 9000 19.8: an empty STREAM frame (length 0) still carries the LEN bit
 * with a zero Length varint and round-trips. */
static void test_stream_frame_empty(void) {
  u8  out[32];
  usz olen = 0;
  CHECK(appdata_frame_flat(8, 0, (const u8*)"", 0, 1, out, sizeof(out), &olen));
  CHECK(out[0] == (QUIC_FRAME_STREAM_BASE | QUIC_STREAM_LEN | QUIC_STREAM_FIN));

  quic_stream_frame f;
  CHECK(quic_frame_get_stream(out, olen, &f) == olen);
  CHECK(f.stream_id == 8);
  CHECK(f.length == 0);
  CHECK(f.fin == 1);
}

/* No room: returns 0. */
static void test_stream_frame_overflow(void) {
  const u8 data[] = {1, 2, 3, 4, 5};
  u8       out[2];
  usz      olen = 0;
  CHECK(!appdata_frame_flat(
      0, 0, data, sizeof(data), 0, out, sizeof(out), &olen));
}

void test_stream_send(void) {
  test_stream_frame_basic();
  test_stream_frame_off_fin();
  test_stream_frame_off_nofin();
  test_stream_frame_empty();
  test_stream_frame_overflow();
}
