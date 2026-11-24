#ifndef NOSTREV_FIXTURES_H
#define NOSTREV_FIXTURES_H
/* clang-format off */
/* NIP-01 / NIP-98 fixtures signed by nostr-tools 2.25.5 (finalizeEvent,
 * nip98.getToken with includeAuthorizationScheme and Date pinned to
 * 1732400000 s), secret key 0x00..07. Non-printable and non-ASCII bytes
 * are octal escapes of the UTF-8 the library produced. */
static const char nostrev_fx_e1[] =
    "{\"kind\":1,\"created_at\":1700000000,\"tags\":[[\"e\",\"5c83da77af1d"
    "ec6d7289834998ad7aafbd9e2191396d75ec3cc27f5a77226f36\",\"wss:/"
    "/r.example/\"],[\"p\",\"x\"],[\"t\",\"\346\227\245\346\234\254\"]],\"content\":\"hello \\\"q"
    "\\\" \\\\ a/b\\nn\\tt\\rr\\b\\f \303\251 \360\237\230\200 \177 <&>\",\"pubkey\":\"5cbdf0646e5d"
    "b4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc\",\"id\":\""
    "9cc9531bd4a9cc0afc3fac1c03ec207b7e4c07892ce8be8c3e6281052fe7"
    "ca2f\",\"sig\":\"c4b57e08561994858fe9c36e91a475d04388b293c963c06"
    "e0cd3ffc7082eef21da05d9aac940d834429443aa82d131ee8cc2057f250"
    "8303fd0747360b03af5af\"}";
/* serializeEvent(e1): the canonical form its id hashes. */
static const char nostrev_fx_e1_ser[] =
    "[0,\"5cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bdded"
    "cac4f9bc\",1700000000,1,[[\"e\",\"5c83da77af1dec6d7289834998ad7a"
    "afbd9e2191396d75ec3cc27f5a77226f36\",\"wss://r.example/\"],[\"p\""
    ",\"x\"],[\"t\",\"\346\227\245\346\234\254\"]],\"hello \\\"q\\\" \\\\ a/b\\nn\\tt\\rr\\b\\f \303\251 \360\237"
    "\230\200 \177 <&>\"]";
static const char nostrev_fx_t2[] =
    "Nostr eyJraW5kIjoyNzIzNSwidGFncyI6W1sidSIsImh0dHBzOi8vaHViLm"
    "V4YW1wbGUvbW9xP3Jvb209cjEiXSxbIm1ldGhvZCIsIkNPTk5FQ1QiXV0sIm"
    "NyZWF0ZWRfYXQiOjE3MzI0MDAwMDAsImNvbnRlbnQiOiIiLCJwdWJrZXkiOi"
    "I1Y2JkZjA2NDZlNWRiNGVhYTM5OGYzNjVmMmVhN2EwZTNkNDE5YjdlMDMzMG"
    "UzOWNlOTJiZGRlZGNhYzRmOWJjIiwiaWQiOiJhYWE1NDMxMzVmYWJlZGQ1ND"
    "g2NjdhN2FjYzYxMWI5ZDFmZDgwMzRiZmUwYWU1YjQ5YmE3MTJhZjMxZjJjYW"
    "YxIiwic2lnIjoiYWU2MWQzMGU2OThhODAwZTI4NmEyZTU3NjJkMzY4NjYxOT"
    "U2OGYyNzhjY2FhMTNlOTZiYjczMjc0YWQ4MzRmMDE0ZDdiODFkYWJkMTBkMD"
    "kxMmU0NWRjYTBjZTA3MjVhMTgwYTRhYzZjYTliZDQ4MmQ3ZDYxMDZmYWQ1ZT"
    "Y4ODcifQ==";
static const char nostrev_fx_t3[] =
    "Nostr eyJraW5kIjoyNzIzNSwidGFncyI6W1sidSIsImh0dHBzOi8vaHViLm"
    "V4YW1wbGUvdXBsb2FkIl0sWyJtZXRob2QiLCJQT1NUIl0sWyJwYXlsb2FkIi"
    "wiMDE1YWJkN2Y1Y2M1N2EyZGQ5NGI3NTkwZjA0YWQ4MDg0MjczOTA1ZWUzM2"
    "VjNWNlYmVhZTYyMjc2YTk3Zjg2MiJdXSwiY3JlYXRlZF9hdCI6MTczMjQwMD"
    "AwMCwiY29udGVudCI6IiIsInB1YmtleSI6IjVjYmRmMDY0NmU1ZGI0ZWFhMz"
    "k4ZjM2NWYyZWE3YTBlM2Q0MTliN2UwMzMwZTM5Y2U5MmJkZGVkY2FjNGY5Ym"
    "MiLCJpZCI6ImY3NjFhZGE2NjU4YTMwZDc4MmU2NDRhMmYxZjFiOTMxZjQzZD"
    "ViMjA1M2Y5OTdmNDM1N2IzMGJmOWUzM2VmNWQiLCJzaWciOiIzN2U1YWE0Zm"
    "FmYTc0MGNjOWE3M2NiNDA4ZGJhMjAwNDI0ZThlMWUzYjZjY2U1NjUyOTg4ZT"
    "Q5ZGU0ZmJiYTU4ZmQ5YzIzM2ZlMTY3YTdkNjE2MmJkY2Q2Njc2MmVlZDFmZD"
    "M2NGIxNDdmYWU5Yzk4NjI2YzU2ZDlmMThjMGFiZSJ9";
static const char nostrev_fx_e3[] =
    "{\"kind\":27235,\"tags\":[[\"u\",\"https://hub.example/upload\"],[\"m"
    "ethod\",\"POST\"],[\"payload\",\"015abd7f5cc57a2dd94b7590f04ad8084"
    "273905ee33ec5cebeae62276a97f862\"]],\"created_at\":1732400000,\""
    "content\":\"\",\"pubkey\":\"5cbdf0646e5db4eaa398f365f2ea7a0e3d419b"
    "7e0330e39ce92bddedcac4f9bc\",\"id\":\"f761ada6658a30d782e644a2f1"
    "f1b931f43d5b2053f997f4357b30bf9e33ef5d\",\"sig\":\"37e5aa4fafa74"
    "0cc9a73cb408dba200424e8e1e3b6cce5652988e49de4fbba58fd9c233fe"
    "167a7d6162bdcd66762eed1fd364b147fae9c98626c56d9f18c0abe\"}";
#endif
