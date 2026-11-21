#ifndef RPSTEER_RPSTEER_H
#define RPSTEER_RPSTEER_H

#include "common/platform/sys/syscall.h"
#include "transport/packet/frame/frame/ncid_worker.h"

/** @file
 * SO_REUSEPORT socket-selection program builder (classic BPF): route each
 * datagram of a multi-worker UDP run to the reuseport-group member whose
 * index the QUIC Destination Connection ID carries -- the same keyed
 * routing byte the AF_XDP path embeds and decodes (ncid_route_encode /
 * xdpbpf, RFC 9312 2.6), so a server-issued CID keeps reaching the worker
 * that holds its connection after a NAT rebinding or migration (RFC 9000
 * 5.2, 9). Classic BPF on purpose: SO_ATTACH_REUSEPORT_CBPF needs no
 * bpf(2) syscall and no privilege, unlike the eBPF form. cBPF has only
 * 32-bit ALU, so ncid_route_mask's two 64-bit multiplies are recomputed
 * from 32x32-bit partial products (rpsteer.c, proven equal to the 64-bit
 * reference in tests/transport/rpsteer_test.c).
 *
 * The kernel runs the program with data starting at the UDP payload, i.e.
 * offset 0 is the QUIC header's first byte. A short header's DCID starts at
 * offset 1 (RFC 9000 17.3), a long header's at offset 6 (RFC 9000 17.2:
 * flags + 4-byte version + DCID length byte). The program returns the
 * decoded routing byte when it is < nsock, selecting that group member
 * (group index == bind order, so the driver must bind worker sockets in
 * worker order -- srvsteer does); anything else -- a decode out of range
 * (e.g. a client's self-chosen first-Initial DCID, RFC 9000 7.2), or a
 * datagram too short to carry NCID_ROUTE_MIN_LEN DCID bytes -- returns
 * 0xffffffff, which the kernel treats as "no selection" and falls back to
 * its 4-tuple hash. Routing is therefore guaranteed only for packets whose
 * DCID this server issued; a first flight rides the (per-4-tuple-stable)
 * hash or a uniformly random in-range decode, both deterministic for a
 * retransmission's identical bytes. */

/** Number of 8-byte classic-BPF instructions rpsteer_prog_build emits. */
#define RPSTEER_PROG_LEN 145

/** Pack one struct sock_filter {u16 code; u8 jt; u8 jf; u32 k} into a u64
 * (little-endian field layout), mirroring xdpbpf_bpf_insn for eBPF. */
u64 rpsteer_insn(u16 code, u8 jt, u8 jf, u32 k);

/** Build the reuseport selection program into out: decode the DCID routing
 * byte under key (exactly ncid_route_decode) and return it when < nsock,
 * else return 0xffffffff (kernel hash fallback). Pure function of its
 * arguments. Returns RPSTEER_PROG_LEN. */
usz rpsteer_prog_build(
    u64 out[RPSTEER_PROG_LEN], const ncid_route_key* key, u32 nsock);

#endif
