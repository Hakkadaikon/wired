// probe is the guide's external client: it talks to a snippet server over
// real UDP and prints only what it understood, so the output is stable.
//
//	probe tls      <addr> [n]                             TLS 1.3 handshake over QUIC, n times
//	probe h3get    <addr> <path>...                       HTTP/3 GET each path
//	probe h3req    <addr> METHOD path [-H 'k: v']... [--body-file f]  one HTTP/3 request
//	probe wtconnect <addr> [--origin O] path               WebTransport CONNECT, prints status
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/webtransport-go"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: probe tls|h3get|h3req|wtconnect <addr> ...")
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "tls":
		err = probeTLS(os.Args[2], os.Args[3:])
	case "h3get":
		err = h3get(os.Args[2], os.Args[3:])
	case "h3req":
		err = h3req(os.Args[2], os.Args[3:])
	case "wtconnect":
		err = wtConnect(os.Args[2], os.Args[3:])
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

// formatHeaders renders h as sorted "name: value" lines, dropping any header
// whose name looks date-like (Date, Last-Modified, Expires, ...) since those
// vary per run and would break the golden diff.
func formatHeaders(h http.Header) []string {
	names := make([]string, 0, len(h))
	for name := range h {
		if !strings.Contains(strings.ToLower(name), "date") {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	lines := make([]string, len(names))
	for i, name := range names {
		lines[i] = fmt.Sprintf("%s: %s", strings.ToLower(name), strings.Join(h[name], ", "))
	}
	return lines
}

// parseH3req splits "-H 'name: value'" and "--body-file f" out of args,
// returning the request headers and the body file path (empty if none).
func parseH3req(args []string) (http.Header, string, error) {
	hdr := http.Header{}
	bodyFile := ""
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-H":
			if i+1 >= len(args) {
				return nil, "", fmt.Errorf("-H needs 'name: value'")
			}
			i++
			name, value, ok := strings.Cut(args[i], ":")
			if !ok {
				return nil, "", fmt.Errorf("-H %q: want 'name: value'", args[i])
			}
			hdr.Add(strings.TrimSpace(name), strings.TrimSpace(value))
		case "--body-file":
			if i+1 >= len(args) {
				return nil, "", fmt.Errorf("--body-file needs a path")
			}
			i++
			bodyFile = args[i]
		default:
			return nil, "", fmt.Errorf("h3req: unexpected arg %q", args[i])
		}
	}
	return hdr, bodyFile, nil
}

// noRedirect stops http.Client from auto-following a 3xx, so h3req prints
// the server's own response (status, Location header, body) instead of
// whatever the redirect target answered.
func noRedirect(*http.Request, []*http.Request) error {
	return http.ErrUseLastResponse
}

func h3req(addr string, args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("usage: h3req METHOD path [-H 'name: value']... [--body-file f]")
	}
	method, path := args[0], args[1]
	hdr, bodyFile, err := parseH3req(args[2:])
	if err != nil {
		return err
	}
	var body io.Reader
	if bodyFile != "" {
		b, err := os.ReadFile(bodyFile)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, "https://"+addr+path, body)
	if err != nil {
		return err
	}
	req.Header = hdr
	tr := &http3.Transport{TLSClientConfig: tlsConf()}
	defer tr.Close()
	// Show the server's own response, not where a 3xx points to.
	c := &http.Client{Transport: tr, Timeout: 5 * time.Second, CheckRedirect: noRedirect}
	rsp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer rsp.Body.Close()
	respBody, err := io.ReadAll(rsp.Body)
	if err != nil {
		return err
	}
	fmt.Printf("status %d\n", rsp.StatusCode)
	for _, line := range formatHeaders(rsp.Header) {
		fmt.Println(line)
	}
	fmt.Println()
	fmt.Println(string(respBody))
	return nil
}

// wtConnect performs a WebTransport CONNECT (extended CONNECT, :protocol
// webtransport) and prints only the response status, so the output is
// stable across runs.
func wtConnect(addr string, args []string) error {
	origin := ""
	if len(args) >= 2 && args[0] == "--origin" {
		origin = args[1]
		args = args[2:]
	}
	if len(args) < 1 {
		return fmt.Errorf("usage: wtconnect [--origin O] path")
	}
	hdr := http.Header{}
	if origin != "" {
		hdr.Set("Origin", origin)
	}
	d := &webtransport.Transport{TLSClientConfig: tlsConf()}
	defer d.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	rsp, sess, err := d.Dial(ctx, "https://"+addr+args[0], hdr)
	if rsp == nil {
		return err
	}
	fmt.Println(rsp.StatusCode)
	if sess != nil {
		sess.CloseWithError(0, "")
	}
	return nil
}
