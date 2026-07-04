#include "test.h"

/* Local nul-terminated string compare; src/ has no libc strcmp. */
static int mimetype_streq(const char *a, const char *b) {
  usz i = 0;
  for (; a[i] || b[i]; i++)
    if (a[i] != b[i]) return 0;
  return 1;
}

/* Content-Type inference from a file path's extension (last "." segment). */
void test_mimetype(void) {
  CHECK(mimetype_streq(wired_mimetype_for_path("index.html"), "text/html"));
  CHECK(mimetype_streq(wired_mimetype_for_path("style.css"), "text/css"));
  CHECK(mimetype_streq(wired_mimetype_for_path("app.js"), "text/javascript"));
  CHECK(
      mimetype_streq(wired_mimetype_for_path("data.json"), "application/json"));
  CHECK(mimetype_streq(wired_mimetype_for_path("notes.txt"), "text/plain"));
  CHECK(mimetype_streq(wired_mimetype_for_path("pic.png"), "image/png"));
  CHECK(mimetype_streq(wired_mimetype_for_path("pic.jpg"), "image/jpeg"));
  CHECK(mimetype_streq(wired_mimetype_for_path("pic.jpeg"), "image/jpeg"));

  /* no extension -> default */
  CHECK(mimetype_streq(
      wired_mimetype_for_path("README"), "application/octet-stream"));

  /* multiple dots: only the last extension counts */
  CHECK(mimetype_streq(
      wired_mimetype_for_path("archive.tar.gz"), "application/octet-stream"));
  CHECK(mimetype_streq(wired_mimetype_for_path("index.tar.html"), "text/html"));

  /* case sensitivity: simple exact match, uppercase falls to default */
  CHECK(mimetype_streq(
      wired_mimetype_for_path("index.HTML"), "application/octet-stream"));

  /* a dot in a directory segment, no extension on the file itself */
  CHECK(mimetype_streq(
      wired_mimetype_for_path("/foo.d/bar"), "application/octet-stream"));

  /* trailing dot with empty extension -> default */
  CHECK(mimetype_streq(
      wired_mimetype_for_path("weird."), "application/octet-stream"));
}
