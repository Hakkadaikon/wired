# nip05d next to the moqt_chat hub (README.md 4): a static Go binary on
# scratch, with the CA bundle it needs to fetch nostr.json over HTTPS.
FROM golang:1.26 AS build
WORKDIR /src
COPY examples/moqt_chat/nip05d/ .
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /nip05d .

FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=build /nip05d /nip05d
USER 65534:65534
ENTRYPOINT ["/nip05d", "-tcp", "127.0.0.1:4480"]
