# moqt_chat's wired_server as a scratch image: the binary is fully static
# (-ffreestanding -nostdlib -static, see justfile's cflags) and touches no
# filesystem at runtime except the one movie file it reads once at boot
# (its self-signed cert is generated in memory each boot, not read from
# disk -- see selfcert.c), so it needs nothing besides itself and that
# file. Built OUTSIDE this Dockerfile (the repo's pinned clang/ninja
# toolchain lives in flake.nix, not in any public base image):
#
#   just ninja examples/moqt_chat/wired_server
#   docker build -t moqt-chat -f examples/moqt_chat/Dockerfile .
#
# (justfile's `run`/`run-bg` recipes do both steps for you.)
FROM scratch

COPY examples/moqt_chat/wired_server /wired_server
# Published as the hub-owned "movie/init" + clock-paced "movie" live
# tracks (--movie takes a fragmented MP4, see wired_server.c).
COPY assets/movie-live.mp4 /movie.mp4

EXPOSE 4433/udp

ENTRYPOINT ["/wired_server", "--movie", "/movie.mp4"]
