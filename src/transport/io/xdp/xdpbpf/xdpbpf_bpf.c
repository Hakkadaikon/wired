#include "transport/io/xdp/xdpbpf/xdpbpf_impl.h"

static void bpf_prog_long_path(u64 out[XDPBPF_PROG_LEN]);
static void bpf_prog_key_check(u64 out[XDPBPF_PROG_LEN]);
static void bpf_prog_epilogue(u64 out[XDPBPF_PROG_LEN]);
static void bpf_prog_template(u64 out[XDPBPF_PROG_LEN]);
static void prog_load_attach_log(bpf_attr_prog_load* attr, wired_mspan log);

/* idx 24-31: long-header path (RFC 9000 17.2) -- boundary-check up to
 * offset 49 (version(4) + DCID-len(1) byte + the DCID's own first byte),
 * read the explicit DCID length byte at offset 47, fall back on a
 * zero-length DCID (no core id byte exists then), else read the DCID's
 * first byte at offset 48 into r2 the same way the short path does. */
static void bpf_prog_long_path(u64 out[XDPBPF_PROG_LEN]) {
  int i      = BPF_IDX_LONG;
  out[i]     = xdpbpf_bpf_insn(BPF_INSN_MOV64_REG, 5, 2, 0, 0);
  out[i + 1] = xdpbpf_bpf_insn(BPF_INSN_ADD64_IMM, 5, 0, 0, 49);
  out[i + 2] = xdpbpf_bpf_insn(
      BPF_INSN_JGT_REG, 5, 3, xdpbpf_bpf_off(i + 2, BPF_IDX_FALLBACK), 0);
  out[i + 3] = xdpbpf_bpf_insn(BPF_INSN_LDXB, 4, 2, 47, 0);
  out[i + 4] = xdpbpf_bpf_insn(
      BPF_INSN_JNE_IMM, 4, 0, xdpbpf_bpf_off(i + 4, BPF_IDX_HAS_DCID), 0);
  out[i + 5] = xdpbpf_bpf_insn(
      BPF_INSN_JA, 0, 0, xdpbpf_bpf_off(i + 5, BPF_IDX_FALLBACK), 0);
  out[BPF_IDX_HAS_DCID]     = xdpbpf_bpf_insn(BPF_INSN_LDXB, 2, 2, 48, 0);
  out[BPF_IDX_HAS_DCID + 1] = xdpbpf_bpf_insn(
      BPF_INSN_JA, 0, 0,
      xdpbpf_bpf_off(BPF_IDX_HAS_DCID + 1, BPF_IDX_KEY_CHECK), 0);
}

/* idx 32-33 (BPF_IDX_KEY_CHECK, BPF_IDX_KEY_SKIP): the short/long paths both
 * land at KEY_CHECK with the DCID's first byte in r2 -- a client's self-
 * chosen initial DCID (RFC 9000 7.2) is an unconstrained random byte, so
 * unlike the fallback key (rx_queue_index, always < the RX queue count)
 * this key is NOT guaranteed to be a valid XSKMAP index. Values >=
 * BPF_XSKMAP_ENTRIES fall through to KEY_SKIP's target, BPF_IDX_FALLBACK,
 * instead of being handed to bpf_redirect_map(), which would otherwise
 * XDP_PASS the packet on every map-lookup miss (kernel's documented
 * fallback-to-flags behavior) and never reach the AF_XDP socket -- exactly
 * the handshake-drop bug this check closes. The fallback path itself does
 * not need this same check: see its comment.
 *
 * Both jumps here are FORWARD (KEY_CHECK=32 -> FALLBACK=34, KEY_SKIP=33 ->
 * REDIRECT=35): this block sits *before* BPF_IDX_FALLBACK in program order
 * specifically so neither edge is a backward branch. An earlier revision
 * placed the range check right after the fallback's key load, so the
 * fallback instruction fell through into the check and the check's reject
 * edge jumped back to the fallback -- two edges the verifier's CFG walk
 * read as a cycle, and BPF_PROG_LOAD failed with "infinite loop detected"
 * even though runtime execution never loops (the reject edge is taken at
 * most once per packet). Keeping every edge in this filter forward-only
 * avoids relying on the verifier's bounded-loop analysis at all. */
static void bpf_prog_key_check(u64 out[XDPBPF_PROG_LEN]) {
  out[BPF_IDX_KEY_CHECK] = xdpbpf_bpf_insn(
      BPF_INSN_JGE_IMM, 2, 0,
      xdpbpf_bpf_off(BPF_IDX_KEY_CHECK, BPF_IDX_FALLBACK), BPF_XSKMAP_ENTRIES);
  out[BPF_IDX_KEY_SKIP] = xdpbpf_bpf_insn(
      BPF_INSN_JA, 0, 0, xdpbpf_bpf_off(BPF_IDX_KEY_SKIP, BPF_IDX_REDIRECT), 0);
}

/* idx 34,35-41: the rx_queue_index fallback key load (BPF_IDX_FALLBACK, the
 * original template's only routing key before this task -- already bounded
 * by the NIC's actual RX queue count, so it needs no range check of its
 * own), then the shared redirect-map epilogue every path above converges
 * on (BPF_IDX_REDIRECT), and finally the XDP_PASS trap every dport/
 * boundary miss above jumps to (BPF_IDX_PASS). map_fd (idx REDIRECT+0/+1,
 * the LDDW) is patched by the caller after this runs, same as the original
 * template's idx16. */
static void bpf_prog_epilogue(u64 out[XDPBPF_PROG_LEN]) {
  out[BPF_IDX_FALLBACK] = xdpbpf_bpf_insn(BPF_INSN_LDXW, 2, 1, 16, 0);
  out[BPF_IDX_REDIRECT] =
      xdpbpf_bpf_insn(BPF_INSN_LDDW_IMM, 1, BPF_SRC_MAP_FD, 0, 0); /* patched */
  out[BPF_IDX_REDIRECT + 1] = xdpbpf_bpf_insn(0, 0, 0, 0, 0);
  out[BPF_IDX_REDIRECT + 2] =
      xdpbpf_bpf_insn(BPF_INSN_MOV64_IMM, 3, 0, 0, XDP_PASS);
  out[BPF_IDX_REDIRECT + 3] =
      xdpbpf_bpf_insn(BPF_INSN_CALL, 0, 0, 0, BPF_FUNC_REDIRECT_MAP);
  out[BPF_IDX_REDIRECT + 4] = xdpbpf_bpf_insn(BPF_INSN_EXIT, 0, 0, 0, 0);
  out[BPF_IDX_PASS] = xdpbpf_bpf_insn(BPF_INSN_MOV64_IMM, 0, 0, 0, XDP_PASS);
  out[BPF_IDX_PASS + 1] = xdpbpf_bpf_insn(BPF_INSN_EXIT, 0, 0, 0, 0);
}

/* Fixed filter template (see xdpbpf.h for the full semantics); dport
 * (idx14) and map_fd (the LDDW at BPF_IDX_REDIRECT) are patched per call by
 * xdpbpf_prog_build. */
static void bpf_prog_template(u64 out[XDPBPF_PROG_LEN]) {
  xdpbpf_bpf_prog_prologue(out);
  xdpbpf_bpf_prog_header_split(out);
  xdpbpf_bpf_prog_short_path(out);
  bpf_prog_long_path(out);
  bpf_prog_key_check(out);
  bpf_prog_epilogue(out);
}

usz xdpbpf_prog_build(u64 out[XDPBPF_PROG_LEN], i32 map_fd, u16 port) {
  bpf_prog_template(out);
  out[14] = xdpbpf_bpf_insn(
      BPF_INSN_JNE_IMM, 4, 0, xdpbpf_bpf_off(14, BPF_IDX_PASS),
      xdpbpf_bpf_htons(port));
  out[BPF_IDX_REDIRECT] =
      xdpbpf_bpf_insn(BPF_INSN_LDDW_IMM, 1, BPF_SRC_MAP_FD, 0, map_fd);
  return XDPBPF_PROG_LEN;
}

i64 xdpbpf_map_create(u32 max_entries) {
  bpf_attr_map_create attr = {BPF_MAP_TYPE_XSKMAP, 4, 4, max_entries, 0};
  return wired_arch_bpf(BPF_MAP_CREATE, &attr, sizeof attr);
}

i64 xdpbpf_map_set(i64 map_fd, u32 key, u32 xsk_fd) {
  bpf_attr_map_update attr = {(u32)map_fd, (u64)&key, (u64)&xsk_fd, 0};
  return wired_arch_bpf(BPF_MAP_UPDATE_ELEM, &attr, sizeof attr);
}

static void prog_load_attach_log(bpf_attr_prog_load* attr, wired_mspan log) {
  attr->log_level = 1;
  attr->log_size  = (u32)log.n;
  attr->log_buf   = (u64)log.p;
}

i64 xdpbpf_prog_load(const u64* insns, u32 cnt, wired_mspan log) {
  static const u8    license[] = "Dual MIT/GPL";
  bpf_attr_prog_load attr      = {
      BPF_PROG_TYPE_XDP, cnt, (u64)insns, (u64)license, 0, 0, 0};
  if (log.n > 0) {
    prog_load_attach_log(&attr, log);
  }
  return wired_arch_bpf(BPF_PROG_LOAD, &attr, sizeof attr);
}

i64 xdpbpf_link_create(i64 prog_fd, u32 ifindex, u32 flags) {
  bpf_attr_link_create attr = {
      (u32)prog_fd, ifindex, BPF_ATTACH_TYPE_XDP, flags};
  return wired_arch_bpf(BPF_LINK_CREATE, &attr, sizeof attr);
}
