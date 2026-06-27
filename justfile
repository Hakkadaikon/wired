# quic_vibe build. libc-free, x86_64-linux only.

cc := "clang"
cflags := "-target x86_64-linux-gnu -ffreestanding -fno-stack-protector -fno-builtin -nostdlib -static -Wall -Wextra -Werror -O2 -Isrc"
testflags := "-Wall -Wextra -Werror -O2 -Isrc -Itests"

# compile every domain freestanding (proves libc independence) into one .o
build:
    mkdir -p build
    {{cc}} {{cflags}} -c src/sys/sys.c src/varint/varint.c src/packet/header.c src/packet/pnum.c src/tparam/tparam.c src/frame/frame.c src/frame/ack.c src/frame/ncid.c src/protect/protect.c src/net/checksum.c src/net/ipv4.c src/net/udp4.c src/net/memlink.c src/tls/x25519.c src/tls/handshake.c src/tls/schedule.c src/endpoint/endpoint.c src/fsm/fsm.c src/stream/stream.c src/conn/conn.c src/hash/sha256.c src/hash/hmac.c src/hkdf/hkdf.c src/aes/aes.c src/gcm/gcm.c src/chacha/chacha20.c src/chacha/poly1305.c src/chacha/aead.c src/tls/initial.c src/hp/hp.c src/recovery/rtt.c src/recovery/sent.c src/cc/cc.c src/flow/flow.c src/flow/reassemble.c src/io/udp.c src/io/retransmit.c src/frame/stream_ctl.c src/frame/flowctl.c src/frame/connctl.c src/frame/dispatch.c src/error/error.c src/packet/short.c src/packet/retry.c src/packet/vneg.c src/tparam/tpblob.c src/tls/retry_tag.c src/keyupdate/keyupdate.c src/path/path.c src/closelife/closelife.c src/version/version.c
    mv *.o build/

# run all tests (hosted, with assertions)
test:
    mkdir -p build
    {{cc}} {{testflags}} tests/run.c -o build/quic_test && build/quic_test

# cyclomatic complexity gate: CCN must be <= 3
ccn:
    lizard src --CCN 3 -w

# everything
check: ccn test
