// probe is the guide's external client: it talks to a snippet server over
// real UDP and prints only what it understood, so the output is stable.
//
//	probe tls   <addr> [n]       TLS 1.3 handshake over QUIC, n times
//	probe h3get <addr> <path>... HTTP/3 GET each path
package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: probe tls|h3get <addr> ...")
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "tls":
		err = probeTLS(os.Args[2], os.Args[3:])
	case "h3get":
		err = h3get(os.Args[2], os.Args[3:])
	default:
		err = fmt.Errorf("unknown subcommand %q", os.Args[1])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func tlsConf() *tls.Config {
	// The snippets serve a self-signed certificate.
	return &tls.Config{InsecureSkipVerify: true, NextProtos: []string{http3.NextProtoH3}}
}

func probeTLS(addr string, rest []string) error {
	n := 1
	if len(rest) > 0 {
		var err error
		if n, err = strconv.Atoi(rest[0]); err != nil {
			return err
		}
	}
	for i := 0; i < n; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		conn, err := quic.DialAddr(ctx, addr, tlsConf(), nil)
		cancel()
		if err != nil {
			return err
		}
		st := conn.ConnectionState().TLS
		if n == 1 {
			fmt.Println("version:", tls.VersionName(st.Version))
			fmt.Println("cipher:", tls.CipherSuiteName(st.CipherSuite))
			fmt.Println("alpn:", st.NegotiatedProtocol)
		} else {
			fmt.Println("handshake", i+1, "ok:", tls.VersionName(st.Version))
		}
		conn.CloseWithError(0, "")
	}
	return nil
}

func h3get(addr string, paths []string) error {
	tr := &http3.Transport{TLSClientConfig: tlsConf()}
	defer tr.Close()
	c := &http.Client{Transport: tr, Timeout: 5 * time.Second}
	for _, p := range paths {
		rsp, err := c.Get("https://" + addr + p)
		if err != nil {
			return err
		}
		body, err := io.ReadAll(rsp.Body)
		rsp.Body.Close()
		if err != nil {
			return err
		}
		fmt.Printf("GET %s status=%d", p, rsp.StatusCode)
		if ct := rsp.Header.Get("Content-Type"); ct != "" {
			fmt.Printf(" content-type=%s", ct)
		}
		if len(body) > 64 {
			fmt.Printf(" bytes=%d sha256=%x\n", len(body), sha256.Sum256(body))
		} else {
			fmt.Printf(" body=%q\n", body)
		}
	}
	return nil
}
