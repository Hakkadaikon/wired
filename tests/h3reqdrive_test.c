#include "h3reqdrive/request_drive.h"
#include "h3conn/response.h"
#include "appdata/app_send.h"
#include "appdata/app_recv.h"
#include "appdata/stream_send.h"
#include "frame/frame.h"
#include "tls/initial.h"
#include "aes/aes.h"
#include "qpack/dyntable.h"
#include "qpack/dynfind.h"
#include "qpackdyn/field_encode.h"
#include "qpackdyn/field_decode.h"
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
    test_reqdrive_onertt();
    test_reqdrive_response_status();
    test_reqdrive_dynamic_table();
}
