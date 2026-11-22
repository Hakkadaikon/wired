#include "test.h"

/* RFC 9204 rows pinned on the server's shipping path: the client's QPACK
 * encoder stream and request field sections sealed for real and stepped
 * through the sr_sl_* fixture (srvrun_test.c); rfch3_* helpers from
 * srvrun_test.c. Field sections are hand-built per RFC 9204 4.5:
 * the section prefix, then the field line representations. */

/* The client's encoder stream (RFC 9204 4.2: client uni stream 6, type
 * 0x02 at offset 0) carrying instructions ins[0..n) from stream offset
 * off (off 0 adds the type byte). Returns the next offset. */
static usz qp9204_enc(srvrun_conn* c, usz off, const u8* ins, usz n) {
  u8  b[64];
  usz k = 0;
  if (off == 0) {
    b[k++] = H3_STREAM_QPACK_ENCODER;
  }
  bytes_memcpy(b + k, ins, n);
  rfch3_send_stream(c, 6, off, b, k + n, 0);
  return off + k + n;
}

/* The section's lines after the request pseudo-headers GET https "/"
 * (static 17, 23, 1) and :authority localhost (static name 0, literal). */
static usz qp9204_req_lines(u8* fs, usz cap) {
  static const u8 st[] = {0xd1, 0xd7, 0xc1};
  qpack_nameref   auth = {0, 1, 0};
  bytes_memcpy(fs, st, sizeof st);
  return sizeof st +
         qpack_literal_namref_encode(
             wired_mspan_of(fs + sizeof st, cap - sizeof st), &auth, SR_AUTH);
}

/* A GET on stream id whose field section is prefix pfx[0..2), the request
 * pseudo-headers, then the lines tail[0..tn), sent with FIN. */
static void qp9204_get(
    srvrun_conn* c, u64 id, const u8* pfx, const u8* tail, usz tn) {
  u8  fs[128], h3[160];
  usz n = 2, len = 0;
  fs[0] = pfx[0];
  fs[1] = pfx[1];
  n += qp9204_req_lines(fs + n, sizeof fs - n);
  bytes_memcpy(fs + n, tail, tn);
  rfch3_frame(h3, sizeof h3, &len, H3_FRAME_HEADERS, wired_span_of(fs, n + tn));
  rfch3_send_stream(c, id, 0, h3, len, 1);
}

/* RFC 9204 2.2 (9204-003): field lines come out in the order of their
 * representations. A GET whose regular lines mix a literal name (x-one),
 * a static name reference (user-agent, 95), an indexed static line
 * (accept-encoding, 31) and another literal name (x-two) reaches the
 * handler with its headers in exactly that order. */
static void test_srvrun_rfc9204_field_lines_in_order(void) {
  static const u8 pfx[] = {0x00, 0x00};
  sr_net          n;
  srvrun_conn*    c = rfch3_fixture(&n);
  u8              lines[96];
  wired_obuf      lb = obuf_of(lines, sizeof lines);
  qpack_nameref   ua = {95, 1, 0};
  rfch3_literal(&lb, "x-one", "1");
  lb.len += qpack_literal_namref_encode(
      wired_mspan_of(lines + lb.len, sizeof lines - lb.len), &ua,
      wired_span_of((const u8*)"t", 1));
  lb.len += qpack_indexed_encode(
      wired_mspan_of(lines + lb.len, sizeof lines - lb.len), 31, 1);
  rfch3_literal(&lb, "x-two", "2");
  qp9204_get(c, 0, pfx, lines, lb.len);
  CHECK(g_rfch3.calls == 1 && g_rfch3.n == 4);
  CHECK(rfch3_hdr_is(0, "x-one", "1"));
  CHECK(rfch3_hdr_is(1, "user-agent", "t"));
  CHECK(rfch3_hdr_is(2, "accept-encoding", "gzip, deflate, br"));
  CHECK(rfch3_hdr_is(3, "x-two", "2"));
  sr_net_close(&n);
}

/* RFC 9204 3.2 (9204-012): a dynamic-table entry duplicating another's
 * name and value is not an error. The encoder stream sets capacity 220,
 * inserts x-dup: v, Duplicates it and inserts x-dup: v once more; a GET
 * referencing all three entries (Required Insert Count 3, encoded 4 --
 * RFC 9204 4.5.1.1 -- Base 3) is answered with three x-dup: v headers and the
 * connection stays up. */
static void test_srvrun_rfc9204_duplicate_entries_ok(void) {
  static const u8 ins[]  = {0x3f, 0xbd, 0x01, /* cap 220 */
                            0x45, 'x',  '-',  'd', 'u', 'p', 0x01, 'v',
                            0x00, /* dup 0 */
                            0x45, 'x',  '-',  'd', 'u', 'p', 0x01, 'v'};
  static const u8 pfx[]  = {0x04, 0x00};
  static const u8 refs[] = {0x82, 0x81, 0x80}; /* absolute 0, 1, 2 */
  sr_net          n;
  srvrun_conn*    c = rfch3_fixture(&n);
  qp9204_enc(c, 0, ins, sizeof ins);
  CHECK(!c->closing && c->l.h3.qdyn.count == 3);
  qp9204_get(c, 0, pfx, refs, sizeof refs);
  CHECK(!c->closing);
  CHECK(g_rfch3.calls == 1 && g_rfch3.n == 3);
  for (usz i = 0; i < 3; i++) {
    CHECK(rfch3_hdr_is(i, "x-dup", "v"));
  }
  sr_net_close(&n);
}

/* RFC 9204 3.2.2 (9204-057): the server starts the peer's dynamic table at
 * capacity 0, so an insert received before any Set Dynamic Table Capacity
 * is larger than the capacity: QPACK_ENCODER_STREAM_ERROR closes the
 * connection and nothing was inserted. */
static void test_srvrun_rfc9204_insert_before_capacity_fails(void) {
  static const u8 ins[] = {0x45, 'x', '-', 'd', 'u', 'p', 0x01, 'v'};
  sr_net          n;
  srvrun_conn*    c      = rfch3_fixture(&n);
  int             is_app = 0;
  CHECK(c->l.h3.qdyn.capacity == 0);
  qp9204_enc(c, 0, ins, sizeof ins);
  CHECK(c->l.h3.qdyn.count == 0);
  CHECK(c->closing);
  CHECK(sr_close_code(c, &is_app) == QPACK_ENCODER_STREAM_ERROR && is_app);
  sr_net_close(&n);
}

/* RFC 9204 3.2.2 (9204-065): an insert that evicts the very entry it
 * references still inserts that entry's name and value. Capacity 39 holds
 * exactly one 39-byte entry (6 + 1 + 32): x-aaaa: 1. An Insert With Name
 * Reference to it (value 2) evicts it, yet the new entry is x-aaaa: 2; a
 * Duplicate of that one evicts it in turn and copies x-aaaa: 2. A GET
 * after each (Required Insert Count 2 then 3, encoded 3 and 4: MaxEntries
 * comes from the advertised maximum capacity, RFC 9204 4.5.1.1) sees the
 * referenced entry whole. */
static void test_srvrun_rfc9204_insert_evicting_its_reference(void) {
  static const u8 cap_ins[] = {0x3f, 0x08, /* capacity 39 */
                               0x46, 'x',  '-', 'a', 'a', 'a', 'a', 0x01, '1'};
  static const u8 ref_ins[] = {0x80, 0x01, '2'}; /* name ref dynamic 0 */
  static const u8 dup_ins[] = {0x00};            /* Duplicate dynamic 0 */
  static const u8 pfx2[]    = {0x03, 0x00};      /* RIC 2, Base 2 */
  static const u8 pfx3[]    = {0x04, 0x00};      /* RIC 3, Base 3 */
  static const u8 ref0[]    = {0x80};
  sr_net          n;
  srvrun_conn*    c   = rfch3_fixture(&n);
  usz             off = qp9204_enc(c, 0, cap_ins, sizeof cap_ins);
  off                 = qp9204_enc(c, off, ref_ins, sizeof ref_ins);
  CHECK(!c->closing && c->l.h3.qdyn.count == 1 && c->l.h3.qdyn.dropped == 1);
  qp9204_get(c, 0, pfx2, ref0, 1);
  CHECK(g_rfch3.calls == 1 && g_rfch3.n == 1);
  CHECK(rfch3_hdr_is(0, "x-aaaa", "2"));
  qp9204_enc(c, off, dup_ins, sizeof dup_ins);
  CHECK(!c->closing && c->l.h3.qdyn.count == 1 && c->l.h3.qdyn.dropped == 2);
  qp9204_get(c, 4, pfx3, ref0, 1);
  CHECK(g_rfch3.calls == 2 && g_rfch3.n == 1);
  CHECK(rfch3_hdr_is(0, "x-aaaa", "2"));
  sr_net_close(&n);
}

/* RFC 9204 4.2 (9204-060): the server never closes its encoder or decoder
 * stream. Over a whole connection (rfch3_life) both open with their type
 * byte (0x02 on 7, 0x03 on 11), no STREAM frame on either carries FIN,
 * and neither is reset. */
static void test_srvrun_rfc9204_qpack_streams_never_closed(void) {
  static rfcpin_wire w;
  static const u64   id[2] = {SRVRUN_QENC_STREAM, SRVRUN_QDEC_STREAM};
  static const u8    ty[2] = {H3_STREAM_QPACK_ENCODER, H3_STREAM_QPACK_DECODER};
  rfch3_life(&w);
  for (usz i = 0; i < 2; i++) {
    const rfcpin_stream* s = rfcpin_wire_stream(&w, id[i]);
    CHECK(s != 0);
    CHECK(s && s->end >= 1 && s->b[0] == ty[i] && s->fin == 0);
    CHECK(rfcpin_wire_reset_code(&w, id[i]) == ~0ULL);
  }
}

/* RFC 9114 4.2.2 size of a GET (rfch3_fields' pseudo-headers) plus one
 * x-big header of vlen bytes: name + value + 32 per field line. */
static usz qp9204_section_size(usz vlen) {
  return (7 + 3 + 32) + (7 + 5 + 32) + (10 + SR_AUTH.n + 32) + (5 + 1 + 32) +
         (5 + vlen + 32);
}

/* RFC 9204 7.4 (9204-064): the decoder's limits hold the largest field
 * section the server advertises (SETTINGS_MAX_FIELD_SECTION_SIZE =
 * WIRED_H3_MAX_FIELD_SECTION). A GET whose section is exactly that size
 * (RFC 9114 4.2.2) is decoded whole and reaches the handler. */
static void test_srvrun_rfc9204_max_field_section_decodes(void) {
  static u8          value[WIRED_H3_MAX_FIELD_SECTION], req[2 * BODYWIN_CAP];
  static u8          fs[WIRED_H3_MAX_FIELD_SECTION + 64];
  static const char* nv[2];
  sr_net             n;
  srvrun_conn*       c    = rfch3_fixture(&n);
  wired_obuf         fob  = obuf_of(fs, sizeof fs);
  usz                vlen = WIRED_H3_MAX_FIELD_SECTION - qp9204_section_size(0);
  usz                len  = 0;
  CHECK(qp9204_section_size(vlen) == WIRED_H3_MAX_FIELD_SECTION);
  bytes_memset(value, 'X', vlen);
  value[vlen] = 0;
  nv[0]       = "x-big";
  nv[1]       = (const char*)value;
  rfch3_fields(&fob, "GET", nv, 1);
  rfch3_frame(
      req, sizeof req, &len, H3_FRAME_HEADERS, wired_span_of(fs, fob.len));
  CHECK(len <= BODYWIN_CAP);
  sr_sl_send_stream(c, req, len, 1);
  CHECK(g_rfch3.calls == 1 && g_rfch3.n == 1);
  CHECK(wired_cstr_eq((const char*)g_rfch3.name[0], "x-big"));
  CHECK(g_rfch3.vlen[0] == vlen);
  sr_net_close(&n);
}

/* A GET whose only regular line is user-agent (static name 95) with a
 * Huffman-coded value of vlen 'a's (5-bit code, RFC 7541 Appendix B: the
 * encoded request stays well inside the request window), sent with FIN. */
static void qp9204_huffman_get(srvrun_conn* c, usz vlen) {
  static u8       value[WIRED_H3_MAX_FIELD_SECTION + 1];
  static u8       lines[WIRED_H3_MAX_FIELD_SECTION], h3[BODYWIN_CAP];
  static const u8 pfx[] = {0x00, 0x00};
  qpack_nameref   ua    = {95, 1, 0};
  usz             ln;
  bytes_memset(value, 'a', vlen);
  ln = qpack_literal_namref_encode(
      wired_mspan_of(lines, sizeof lines), &ua, wired_span_of(value, vlen));
  CHECK(ln != 0 && ln < BODYWIN_CAP - 64);
  {
    u8  fs[BODYWIN_CAP];
    usz k = 2, len = 0;
    fs[0] = pfx[0];
    fs[1] = pfx[1];
    k += qp9204_req_lines(fs + k, sizeof fs - k);
    bytes_memcpy(fs + k, lines, ln);
    rfch3_frame(
        h3, sizeof h3, &len, H3_FRAME_HEADERS, wired_span_of(fs, k + ln));
    sr_sl_send_stream(c, h3, len, 1);
  }
}

/* RFC 9204 7.4 (9204-064), past the limit: a section whose decoded lines
 * need one byte more than the decode scratch (WIRED_H3_MAX_FIELD_SECTION:
 * localhost's 9 bytes plus the value) -- itself past the advertised size
 * -- fails cleanly: a 431 answer (RFC 6585 5), the handler never runs,
 * the connection stays up. */
static void test_srvrun_rfc9204_past_scratch_fails_cleanly(void) {
  sr_net       n;
  srvrun_conn* c = rfch3_fixture(&n);
  qp9204_huffman_get(c, WIRED_H3_MAX_FIELD_SECTION - SR_AUTH.n + 1);
  CHECK(g_rfch3.calls == 0);
  CHECK(!c->closing);
  CHECK(sr_resp_is_status(&c->resp[0], 0, 431));
  sr_net_close(&n);
}

void test_srvrun_rfc9204(void) {
  test_srvrun_rfc9204_field_lines_in_order();
  test_srvrun_rfc9204_duplicate_entries_ok();
  test_srvrun_rfc9204_insert_before_capacity_fails();
  test_srvrun_rfc9204_insert_evicting_its_reference();
  test_srvrun_rfc9204_qpack_streams_never_closed();
  test_srvrun_rfc9204_max_field_section_decodes();
  test_srvrun_rfc9204_past_scratch_fails_cleanly();
}
