# quic-interop-runner endpoint image for wired (server role).
#
# The freestanding binary is built OUTSIDE this Dockerfile (it needs the
# repo's pinned clang/ninja toolchain):
#
#   just ninja examples/word_list/wired_server
#   docker build -t wired-interop -f interop/Dockerfile .
#
# The runner's network-simulator base image supplies the wait-for-it
# behavior; endpoints derive from it per the interop-runner contract.
FROM martenseemann/quic-network-simulator-endpoint:latest

# iptables: the connectionmigration testcase REDIRECTs the advertised
# preferred port (udp/4433) onto the single 443 socket (run_endpoint.sh).
RUN apt-get update &&                                        \
    apt-get install -y --no-install-recommends iptables &&   \
    rm -rf /var/lib/apt/lists/*

COPY examples/word_list/wired_server /wired/wired_server
COPY interop/run_endpoint.sh /run_endpoint.sh
RUN chmod +x /run_endpoint.sh /wired/wired_server

ENTRYPOINT ["/run_endpoint.sh"]
