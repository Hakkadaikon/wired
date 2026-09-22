# moqt_chat's wired_server as a scratch image: the binary is fully static
# (-ffreestanding -nostdlib -static, see justfile's cflags) and touches no
# filesystem at runtime (its self-signed cert is generated in memory each
# boot, not read from disk -- see selfcert.c), so it needs nothing besides
# itself. Built OUTSIDE this Dockerfile (the repo's pinned clang/ninja
# toolchain lives in flake.nix, not in any public base image):
#
#   just ninja examples/moqt_chat/wired_server
#   docker build -t moqt-chat -f examples/moqt_chat/Dockerfile .
#
# (justfile's `run`/`run-bg` recipes do both steps for you.)
FROM scratch

COPY examples/moqt_chat/wired_server /wired_server

EXPOSE 4433/udp

ENTRYPOINT ["/wired_server"]
