#include "app/http3/request/h3reqdrive/request_drive.h"
#include "app/http3/core/h3conn/response.h"
#include "transport/stream/data/appdata/app_send.h"
#include "transport/stream/data/appdata/app_recv.h"
#include "transport/stream/data/appdata/stream_send.h"
#include "transport/packet/frame/frame/frame.h"
#include "tls/handshake/core/tls/initial.h"
#include "crypto/symmetric/aead/aes/aes.h"
#include "app/qpack/qpack/dyntable.h"
#include "app/qpack/qpack/dynfind.h"
#include "app/qpack/qpackdyn/field_encode.h"
#include "app/qpack/qpackdyn/field_decode.h"
#include "app/qpack/qpack/prefix.h"
#include "app/qpack/qpack/fieldline.h"
#include "app/qpack/qpack/literal.h"
#include "app/http3/core/h3conn/request.h"
#include "app/http3/core/h3/frame.h"
#include "test.h"

static int rd_eq(const u8 *a, usz alen, const char *b, usz blen)
{
    if (alen != blen) return 0;
    for (usz i = 0; i < alen; i++)
        if (a[i] != (u8)b[i]) return 0;
    return 1;
}

/* RFC 9114 4.3.1: client encodes a GET, server decodes the field section and
 * recovers all four request pseudo-headers from one STREAM frame. */
static void test_reqdrive_stream(void)
{
    const u8 path[] = {'/', 'i', 'n', 'd', 'e', 'x'};
    const u8 auth[] = {'e', 'x', '.', 'c', 'o', 'm'};
    u8 req[256], scratch[128];
    usz req_len = 0;
    quic_h3reqdrive_req r;

    CHECK(quic_h3reqdrive_send_get(0, path, sizeof(path), auth, sizeof(auth),
                                   req, sizeof(req), &req_len));
    CHECK(quic_h3reqdrive_recv_get(req, req_len, scratch, sizeof(scratch), &r));
    CHECK(rd_eq(r.method, r.method_len, "GET", 3));
    CHECK(rd_eq(r.scheme, r.scheme_len, "https", 5));
    CHECK(rd_eq(r.authority, r.authority_len, "ex.com", 6));
    CHECK(rd_eq(r.path, r.path_len, "/index", 6));
    CHECK(r.body_len == 0);   /* GET carries no DATA frame */
}

/* RFC 9114 4.1: a request = HEADERS [DATA...]. A POST with a body decodes its
 * :method and views the DATA-frame body. */
static void test_reqdrive_post_body(void)
{
    static const u8 method[] = {'P', 'O', 'S', 'T'};
    const u8 path[] = {'/', 'u'};
    const u8 auth[] = {'h', '1'};
    const u8 body[] = {'h', 'e', 'l', 'l', 'o'};
    u8 req[256], scratch[128];
    usz req_len = 0;
    quic_h3reqdrive_req r;

    CHECK(quic_h3reqdrive_send_method(0, method, sizeof(method), path,
                                      sizeof(path), auth, sizeof(auth), body,
                                      sizeof(body), req, sizeof(req), &req_len));
    CHECK(quic_h3reqdrive_recv_get(req, req_len, scratch, sizeof(scratch), &r));
    CHECK(rd_eq(r.method, r.method_len, "POST", 4));
    CHECK(rd_eq(r.body, r.body_len, "hello", 5));
}

/* RFC 9114 4.1: an empty body (DATA frame of length 0) decodes to body_len 0
 * but is distinguished from a malformed remainder by succeeding. */
static void test_reqdrive_empty_body(void)
{
    static const u8 method[] = {'P', 'U', 'T'};
    const u8 path[] = {'/', 'e'};
    const u8 auth[] = {'h', '1'};
    const u8 dummy = 0;
    u8 req[256], scratch[128];
    usz req_len = 0;
    quic_h3reqdrive_req r;

    CHECK(quic_h3reqdrive_send_method(0, method, sizeof(method), path,
                                      sizeof(path), auth, sizeof(auth), &dummy,
                                      0, req, sizeof(req), &req_len));
    CHECK(quic_h3reqdrive_recv_get(req, req_len, scratch, sizeof(scratch), &r));
    CHECK(rd_eq(r.method, r.method_len, "PUT", 3));
    CHECK(r.body_len == 0);
}

/* Length of a NUL-terminated literal (test-local). */
static usz cstr(const char *s) { usz i = 0; while (s[i]) i++; return i; }

/* RFC 9204 4.5.6: a Literal Field Line With Literal Name carrying (name,value),
 * appended at *off in fs. */
static void put_litname(u8 *fs, usz *off, const char *name, const char *value)
{
    *off += quic_qpack_literal_name_encode(fs + *off, 64, 0, (const u8 *)name,
                                           cstr(name), (const u8 *)value,
                                           cstr(value));
}

/* RFC 9114 4.3.1 / RFC 9204 4.5: build a curl/quiche-style request field
 * section: pseudo-headers in :method,:authority,:scheme,:path order using a
 * mix of indexed, name-reference and literal-name forms, plus a regular
 * user-agent header as a literal-name line. */
static usz curl_field_section(u8 *fs)
{
    quic_qpack_prefix pfx = {0, 0, 0};
    usz off = quic_qpack_prefix_encode(fs, 64, &pfx);
    off += quic_qpack_indexed_encode(fs + off, 64, 17, 1);   /* :method GET */
    put_litname(fs, &off, ":authority", "curl.test");
    off += quic_qpack_indexed_encode(fs + off, 64, 23, 1);   /* :scheme https */
    off += quic_qpack_literal_namref_encode(fs + off, 64, 1, 1, 0,
                                            (const u8 *)"/get", 4); /* :path */
    put_litname(fs, &off, "user-agent", "curl/8");
    return off;
}

/* RFC 9114 4.1 / RFC 9204 4.5: a curl-style GET (reordered pseudo-headers,
 * mixed encodings, an extra regular header) decodes; all four pseudo-headers
 * are recovered by name regardless of order or count. */
static void test_reqdrive_curl_get(void)
{
    u8 fs[64], req[256], scratch[128];
    usz fs_len = curl_field_section(fs), req_len = 0;
    quic_h3reqdrive_req r;

    CHECK(quic_h3conn_send_request(0, fs, fs_len, 0, 0, req, sizeof(req),
                                   &req_len));
    CHECK(quic_h3reqdrive_recv_get(req, req_len, scratch, sizeof(scratch), &r));
    CHECK(rd_eq(r.method, r.method_len, "GET", 3));
    CHECK(rd_eq(r.scheme, r.scheme_len, "https", 5));
    CHECK(rd_eq(r.authority, r.authority_len, "curl.test", 9));
    CHECK(rd_eq(r.path, r.path_len, "/get", 4));
}

/* RFC 9114 7.2.8: a real GREASE frame as sent by curl/quiche: a reserved type
 * 0x1f*N+0x21 (here matching the on-wire 8-byte varint type) carrying the
 * "GREASE is the word" payload. Returns bytes written. */
static usz put_grease_frame(u8 *buf, usz cap)
{
    const u8 g[] = {'G','R','E','A','S','E',' ','i','s',' ',
                    't','h','e',' ','w','o','r','d'};
    return quic_h3_frame_put(buf, cap, 0x1f * 0x4000 + 0x21, g, sizeof(g));
}

/* RFC 9114 9 / 7.2.8: a request stream that begins with a GREASE frame before
 * the HEADERS frame (exactly what curl/quiche send) must skip the unknown
 * frame and still recover all four request pseudo-headers from the HEADERS. */
static void test_reqdrive_leading_grease(void)
{
    u8 fs[64], h3[256], req[256], scratch[128];
    usz fs_len = curl_field_section(fs), h3_len = 0, req_len = 0;
    quic_h3reqdrive_req r;

    h3_len = put_grease_frame(h3, sizeof(h3));
    h3_len += quic_h3_frame_put(h3 + h3_len, sizeof(h3) - h3_len,
                                QUIC_H3_FRAME_HEADERS, fs, fs_len);
    CHECK(quic_appdata_stream_frame(0, 0, h3, h3_len, 1, req, sizeof(req),
                                    &req_len));
    CHECK(quic_h3reqdrive_recv_get(req, req_len, scratch, sizeof(scratch), &r));
    CHECK(rd_eq(r.method, r.method_len, "GET", 3));
    CHECK(rd_eq(r.scheme, r.scheme_len, "https", 5));
    CHECK(rd_eq(r.authority, r.authority_len, "curl.test", 9));
    CHECK(rd_eq(r.path, r.path_len, "/get", 4));
}

/* RFC 9114 9: two consecutive unknown frames before HEADERS are both skipped. */
static void test_reqdrive_two_greases(void)
{
    u8 fs[64], h3[256], req[256], scratch[128];
    usz fs_len = curl_field_section(fs), h3_len = 0, req_len = 0;
    quic_h3reqdrive_req r;

    h3_len = put_grease_frame(h3, sizeof(h3));
    h3_len += put_grease_frame(h3 + h3_len, sizeof(h3) - h3_len);
    h3_len += quic_h3_frame_put(h3 + h3_len, sizeof(h3) - h3_len,
                                QUIC_H3_FRAME_HEADERS, fs, fs_len);
    CHECK(quic_appdata_stream_frame(0, 0, h3, h3_len, 1, req, sizeof(req),
                                    &req_len));
    CHECK(quic_h3reqdrive_recv_get(req, req_len, scratch, sizeof(scratch), &r));
    CHECK(rd_eq(r.path, r.path_len, "/get", 4));
}

/* RFC 9114 9: a stream carrying only GREASE and no HEADERS must be rejected. */
static void test_reqdrive_grease_only(void)
{
    u8 h3[256], req[256], scratch[128];
    usz h3_len = put_grease_frame(h3, sizeof(h3)), req_len = 0;
    quic_h3reqdrive_req r;

    CHECK(quic_appdata_stream_frame(0, 0, h3, h3_len, 1, req, sizeof(req),
                                    &req_len));
    CHECK(quic_h3reqdrive_recv_get(req, req_len, scratch, sizeof(scratch), &r)
          == 0);
}

/* RFC 9114 9 / 4.1: a leading GREASE frame is skipped and the DATA frame after
 * HEADERS is still read as the body. */
static void test_reqdrive_grease_then_body(void)
{
    u8 fs[64], h3[256], req[256], scratch[128];
    usz fs_len = curl_field_section(fs), h3_len = 0, req_len = 0;
    const u8 body[] = {'b', 'o', 'd', 'y'};
    quic_h3reqdrive_req r;

    h3_len = put_grease_frame(h3, sizeof(h3));
    h3_len += quic_h3_frame_put(h3 + h3_len, sizeof(h3) - h3_len,
                                QUIC_H3_FRAME_HEADERS, fs, fs_len);
    h3_len += quic_h3_frame_put(h3 + h3_len, sizeof(h3) - h3_len,
                                QUIC_H3_FRAME_DATA, body, sizeof(body));
    CHECK(quic_appdata_stream_frame(0, 0, h3, h3_len, 1, req, sizeof(req),
                                    &req_len));
    CHECK(quic_h3reqdrive_recv_get(req, req_len, scratch, sizeof(scratch), &r));
    CHECK(rd_eq(r.path, r.path_len, "/get", 4));
    CHECK(rd_eq(r.body, r.body_len, "body", 4));
}

/* RFC 9114 9 / 4.1: the DATA frame does not have to sit immediately after
 * HEADERS. An unknown/GREASE frame between HEADERS and DATA (curl interleaves
 * these) must be skipped and the DATA body still recovered. */
static void test_reqdrive_data_after_grease(void)
{
    u8 fs[64], h3[256], req[256], scratch[128];
    usz fs_len = curl_field_section(fs), h3_len = 0, req_len = 0;
    const u8 body[] = {'p', 'a', 'y'};
    quic_h3reqdrive_req r;

    h3_len = quic_h3_frame_put(h3, sizeof(h3), QUIC_H3_FRAME_HEADERS, fs, fs_len);
    h3_len += put_grease_frame(h3 + h3_len, sizeof(h3) - h3_len);
    h3_len += quic_h3_frame_put(h3 + h3_len, sizeof(h3) - h3_len,
                                QUIC_H3_FRAME_DATA, body, sizeof(body));
    CHECK(quic_appdata_stream_frame(0, 0, h3, h3_len, 1, req, sizeof(req),
                                    &req_len));
    CHECK(quic_h3reqdrive_recv_get(req, req_len, scratch, sizeof(scratch), &r));
    CHECK(rd_eq(r.path, r.path_len, "/get", 4));
    CHECK(rd_eq(r.body, r.body_len, "pay", 3));
}

/* RFC 9114 4.1: with two DATA frames present, the first one is viewed (the
 * later frame is not joined; documented limitation). */
static void test_reqdrive_multi_data(void)
{
    u8 fs[64], h3[256], req[256], scratch[128];
    usz fs_len = curl_field_section(fs), h3_len = 0, req_len = 0;
    const u8 a[] = {'a', 'a'}, b[] = {'b', 'b'};
    quic_h3reqdrive_req r;

    h3_len = quic_h3_frame_put(h3, sizeof(h3), QUIC_H3_FRAME_HEADERS, fs, fs_len);
    h3_len += quic_h3_frame_put(h3 + h3_len, sizeof(h3) - h3_len,
                                QUIC_H3_FRAME_DATA, a, sizeof(a));
    h3_len += quic_h3_frame_put(h3 + h3_len, sizeof(h3) - h3_len,
                                QUIC_H3_FRAME_DATA, b, sizeof(b));
    CHECK(quic_appdata_stream_frame(0, 0, h3, h3_len, 1, req, sizeof(req),
                                    &req_len));
    CHECK(quic_h3reqdrive_recv_get(req, req_len, scratch, sizeof(scratch), &r));
    CHECK(rd_eq(r.body, r.body_len, "aa", 2));
}

/* RFC 9001 5: derive a shared 1-RTT key pair for the end-to-end path. */
static void rd_keys(quic_initial_keys *k, quic_aes128 *hp)
{
    const u8 dcid[8] = {0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08};
    quic_initial_derive(dcid, 8, 1, k);
    quic_aes128_init(hp, k->hp);
}

/* RFC 9001 5 / RFC 9114 4.1: the GET request is sealed and opened through a
 * real 1-RTT packet before recv_get recovers :authority and :path. */
static void test_reqdrive_onertt(void)
{
    quic_initial_keys k;
    quic_aes128 hp;
    const u8 dcid[4] = {7, 7, 7, 7};
    const u8 path[] = {'/', 'a'};
    const u8 auth[] = {'h', '1'};
    u8 req[256], pkt[256], reframed[256], scratch[128];
    usz req_len = 0, total = 0, rf_len = 0;
    quic_h3reqdrive_req r;
    quic_stream_frame f;
    u64 sid = 0, off = 0;
    const u8 *sdata = 0;
    usz slen = 0;
    int fin = 0;
    rd_keys(&k, &hp);

    CHECK(quic_h3reqdrive_send_get(4, path, sizeof(path), auth, sizeof(auth),
                                   req, sizeof(req), &req_len));
    CHECK(quic_frame_get_stream(req, req_len, &f));
    CHECK(quic_appdata_send(&k, &hp, dcid, 4, 1, f.stream_id, f.data,
                            (usz)f.length, f.fin, pkt, sizeof(pkt), &total));
    CHECK(quic_appdata_recv(&k, &hp, pkt, total, 4, &sid, &off, &sdata, &slen,
                            &fin));
    CHECK(quic_appdata_stream_frame(sid, off, sdata, slen, fin, reframed,
                                    sizeof(reframed), &rf_len));
    CHECK(quic_h3reqdrive_recv_get(reframed, rf_len, scratch, sizeof(scratch),
                                   &r));
    CHECK(rd_eq(r.authority, r.authority_len, "h1", 2));
    CHECK(rd_eq(r.path, r.path_len, "/a", 2));
}

/* RFC 9114 4.1: a 200 response built by h3conn round-trips alongside the
 * driven request so the client recovers :status and body. */
static void test_reqdrive_response_status(void)
{
    const u8 body[] = {'o', 'k'};
    u8 resp[256];
    usz resp_len = 0;
    u16 status = 0;
    const u8 *rbody = 0;
    usz rbody_len = 0;

    CHECK(quic_h3conn_send_response(0, 200, body, sizeof(body), resp,
                                    sizeof(resp), &resp_len));
    CHECK(quic_h3conn_recv_response(resp, resp_len, &status, &rbody,
                                    &rbody_len));
    CHECK(status == 200);
    CHECK(rbody_len == 2 && rbody[0] == 'o' && rbody[1] == 'k');
}

/* RFC 9204 4.5.2: a request value carried as a dynamic-table reference
 * round-trips: insert :authority into the dynamic table, encode the indexed
 * dynamic line, then decode it back to the same (name, value). */
static void test_reqdrive_dynamic_table(void)
{
    quic_qpack_dyn t;
    u8 fs[8];
    usz fs_len = 0, consumed = 0;
    u64 abs, base, rel;
    int matched;
    const u8 *dn, *dv;
    usz dnl, dvl;
    quic_qpack_dyn_init(&t, 4096);

    CHECK(quic_qpack_dyn_insert(&t, (const u8 *)":authority", 10,
                                (const u8 *)"ex.com", 6));
    base = t.dropped + t.count;
    CHECK(quic_qpack_dyn_find(&t, (const u8 *)":authority", 10,
                              (const u8 *)"ex.com", 6, &abs, &matched));
    rel = base - abs - 1;
    CHECK(quic_qdyn_indexed_dynamic(rel, fs, sizeof(fs), &fs_len));
    CHECK(quic_qdyn_decode_field(&t, base, fs, fs_len, 0, &dn, &dnl, &dv, &dvl,
                                 &consumed));
    CHECK(rd_eq(dn, dnl, ":authority", 10));
    CHECK(rd_eq(dv, dvl, "ex.com", 6));
}

void test_h3reqdrive(void)
{
    test_reqdrive_stream();
    test_reqdrive_post_body();
    test_reqdrive_empty_body();
    test_reqdrive_grease_then_body();
    test_reqdrive_data_after_grease();
    test_reqdrive_multi_data();
    test_reqdrive_curl_get();
    test_reqdrive_leading_grease();
    test_reqdrive_two_greases();
    test_reqdrive_grease_only();
    test_reqdrive_onertt();
    test_reqdrive_response_status();
    test_reqdrive_dynamic_table();
}
