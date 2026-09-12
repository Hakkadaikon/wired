/* libFuzzer harness for the fragmented-MP4 top-level box scanner
 * (ISO/IEC 14496-12 box structure, src/app/media/mp4frag). Hosted build
 * only — mirrors tests/run.c's unity-include style, but this file itself
 * may use the standard library since it lives outside src/.
 *
 * The scanner's job is to safely reject arbitrary bytes, so raw input
 * drives mp4frag_scan directly: box-size arithmetic (largesize, size 0,
 * size past end), the moof/mdat pairing rule, and the fragment-count cap
 * are all reachable from data alone. */
#include <stddef.h>
#include <stdint.h>

#include "app/media/mp4frag/mp4frag.c"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  mp4frag_layout out;
  mp4frag_scan(wired_span_of((const u8 *)data, (usz)size), &out);
  return 0;
}
