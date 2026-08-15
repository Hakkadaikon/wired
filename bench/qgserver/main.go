package main

import (
	"flag"
	"net/http"

	"github.com/quic-go/quic-go/http3"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:14434", "listen address")
	root := flag.String("root", ".", "docroot")
	cert := flag.String("cert", "cert.pem", "certificate")
	key := flag.String("key", "key.pem", "private key")
	flag.Parse()
	handler := http.FileServer(http.Dir(*root))
	err := http3.ListenAndServeQUIC(*addr, *cert, *key, handler)
	if err != nil {
		panic(err)
	}
}
