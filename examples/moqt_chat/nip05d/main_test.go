package main

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const pub = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"

// newTestResolver points every dial at an httptest TLS server (cert valid for
// example.com) so the tests stay offline.
func newTestResolver(t *testing.T, allowPrivate bool, h http.HandlerFunc) *resolver {
	t.Helper()
	srv := httptest.NewTLSServer(h)
	t.Cleanup(srv.Close)
	r := newResolver(allowPrivate)
	r.tr.TLSClientConfig = srv.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	r.dialAddr = srv.Listener.Addr().String()
	return r
}

func names(body string) http.HandlerFunc {
	return func(w http.ResponseWriter, q *http.Request) {
		if q.URL.Path != "/.well-known/nostr.json" {
			http.NotFound(w, q)
			return
		}
		fmt.Fprint(w, body)
	}
}

func TestHandle(t *testing.T) {
	big := `{"names":{"bob":"` + pub + `"},"pad":"` + strings.Repeat("x", maxBody) + `"}`
	ok := `{"names":{"bob":"` + pub + `","_":"` + pub + `"}}`
	tests := []struct {
		name, line, want string
		h                http.HandlerFunc
	}{
		{"ok", "check bob@example.com " + pub, "ok", names(ok)},
		{"local part lowercased", "check BOB@Example.COM " + pub, "ok", names(ok)},
		{"root name", "check _@example.com " + pub, "ok", names(ok)},
		{"wrong pubkey", "check bob@example.com " + strings.Repeat("a", 64), "fail mismatch", names(ok)},
		{"missing name", "check carol@example.com " + pub, "fail no-name", names(ok)},
		{"uppercase hex in json", "check bob@example.com " + pub, "fail mismatch", names(`{"names":{"bob":"` + strings.ToUpper(pub) + `"}}`)},
		{"bad json", "check bob@example.com " + pub, "fail bad-json", names(`{"names":[]}`)},
		{"not found", "check bob@example.com " + pub, "fail http-404", http.NotFound},
		{"redirect", "check bob@example.com " + pub, "fail http-302", func(w http.ResponseWriter, q *http.Request) {
			http.Redirect(w, q, "https://example.com/elsewhere", http.StatusFound)
		}},
		{"oversized body", "check bob@example.com " + pub, "fail too-large", names(big)},
		{"body exactly at cap", "check bob@example.com " + pub, "ok", names(ok + strings.Repeat(" ", maxBody-len(ok)))},
		{"ip literal", "check bob@127.0.0.1 " + pub, "fail bad-domain", nil},
		{"ipv6 literal", "check bob@[::1] " + pub, "fail bad-domain", nil},
		{"port in domain", "check bob@example.com:8443 " + pub, "fail bad-domain", nil},
		{"non-ascii domain", "check bob@exämple.com " + pub, "fail bad-request", nil},
		{"kelvin sign folds to k", "check boK@example.com " + pub, "fail bad-request", nil},
		{"invalid utf-8", "check bob@ex\xffample.com " + pub, "fail bad-request", nil},
		{"digit-led tld", "check bob@example.1com " + pub, "fail bad-domain", nil},
		{"hex-looking tld", "check bob@example.0x7f " + pub, "fail bad-domain", nil},
		{"503 is transient", "check bob@example.com " + pub, "unknown http-503", func(w http.ResponseWriter, q *http.Request) { w.WriteHeader(503) }},
		{"429 is transient", "check bob@example.com " + pub, "unknown http-429", func(w http.ResponseWriter, q *http.Request) { w.WriteHeader(429) }},
		{"other names may be non-strings", "check bob@example.com " + pub, "ok", names(`{"names":{"x":123,"bob":"` + pub + `"}}`)},
		{"requested value not a string", "check bob@example.com " + pub, "fail bad-json", names(`{"names":{"bob":123}}`)},
		{"single label", "check bob@localhost " + pub, "fail bad-domain", nil},
		{"empty label", "check bob@example..com " + pub, "fail bad-domain", nil},
		{"hyphen edge label", "check bob@-example.com " + pub, "fail bad-domain", nil},
		{"label 64", "check bob@" + strings.Repeat("a", 64) + ".com " + pub, "fail bad-domain", nil},
		{"domain 254", "check bob@" + strings.Repeat("a.", 125) + "abcd " + pub, "fail bad-domain", nil},
		{"bad local part", "check b+ob@example.com " + pub, "fail bad-name", nil},
		{"empty local part", "check @example.com " + pub, "fail bad-name", nil},
		{"no at", "check example.com " + pub, "fail bad-name", nil},
		{"uppercase pubkey", "check bob@example.com " + strings.ToUpper(pub), "fail bad-pubkey", nil},
		{"short pubkey", "check bob@example.com " + pub[:63], "fail bad-pubkey", nil},
		{"unknown verb", "lookup bob@example.com " + pub, "fail bad-request", nil},
		{"too few fields", "check bob@example.com", "fail bad-request", nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := tc.h
			if h == nil {
				h = func(http.ResponseWriter, *http.Request) { t.Error("must not fetch") }
			}
			r := newTestResolver(t, true, h)
			if got := r.handle(tc.line); got != tc.want {
				t.Fatalf("got %q want %q", got, tc.want)
			}
		})
	}
}

func TestDomain253Accepted(t *testing.T) {
	d := strings.Repeat("a.", 125) + "abc" // 253 chars
	if len(d) != 253 || !validDomain(d) {
		t.Fatal("253-char domain must be valid")
	}
}

func TestTimeoutIsUnknown(t *testing.T) {
	r := newTestResolver(t, true, func(w http.ResponseWriter, q *http.Request) { <-q.Context().Done() })
	r.timeout = 100 * time.Millisecond
	if got := r.handle("check bob@example.com " + pub); got != "unknown timeout" {
		t.Fatalf("got %q", got)
	}
}

func TestNetworkErrorIsUnknown(t *testing.T) {
	r := newResolver(true)
	r.dialAddr = "127.0.0.1:1" // nothing listens
	if got := r.handle("check bob@example.com " + pub); got != "unknown network" {
		t.Fatalf("got %q", got)
	}
}

func TestPrivateAddressRefused(t *testing.T) {
	r := newTestResolver(t, false, names(`{"names":{"bob":"`+pub+`"}}`))
	if got := r.handle("check bob@example.com " + pub); got != "fail forbidden-address" {
		t.Fatalf("got %q", got)
	}
}

func TestForbidden(t *testing.T) {
	for addr, want := range map[string]bool{
		"127.0.0.1": true, "::1": true, "10.1.2.3": true, "172.16.0.1": true,
		"192.168.1.1": true, "169.254.169.254": true, "fe80::1": true,
		"100.64.0.1": true, "100.127.255.255": true, "fc00::1": true, "fd12::1": true,
		"224.0.0.1": true, "ff02::1": true, "0.0.0.0": true, "::": true,
		"::ffff:8.8.8.8": true, "255.255.255.255": true,
		"64:ff9b::a9fe:a9fe": true, "64:ff9b::a00:1": true, "64:ff9b:1::7f00:1": true,
		"2002:7f00:1::1": true, "2001:0::1": true, "2001:db8::1": true, "::7f00:1": true,
		"fec0::1": true, "0.1.2.3": true, "192.0.0.192": true, "198.18.0.1": true,
		"198.19.255.255": true, "240.0.0.1": true, "fe80::1%eth0": true,
		"8.8.8.8": false, "100.128.0.1": false, "2001:4860::8888": false,
		"2600::1": false, "198.20.0.1": false, "192.0.1.1": false,
	} {
		if got := forbidden(netip.MustParseAddr(addr)); got != want {
			t.Errorf("%s: got %v want %v", addr, got, want)
		}
	}
}

func TestCache(t *testing.T) {
	var hits atomic.Int32
	body := `{"names":{"bob":"` + pub + `"}}`
	r := newTestResolver(t, true, func(w http.ResponseWriter, q *http.Request) {
		hits.Add(1)
		fmt.Fprint(w, body)
	})
	now := time.Unix(0, 0)
	r.now = func() time.Time { return now }
	ok, miss := "check bob@example.com "+pub, "check carol@example.com "+pub
	for _, step := range []struct {
		line, want string
		advance    time.Duration
		hits       int32
	}{
		{ok, "ok", 0, 1},
		{ok, "ok", 59 * time.Minute, 1},                                             // positive hit
		{ok, "ok", 2 * time.Minute, 2},                                              // 61 min: expired
		{miss, "fail no-name", 0, 3},                                                // negative stored
		{miss, "fail no-name", 4 * time.Minute, 3},                                  // negative hit
		{miss, "fail no-name", 2 * time.Minute, 4},                                  // 6 min: expired
		{"check bob@example.com " + strings.Repeat("a", 64), "fail mismatch", 0, 5}, // key includes pubkey
	} {
		now = now.Add(step.advance)
		if got := r.handle(step.line); got != step.want || hits.Load() != step.hits {
			t.Fatalf("%q: got %q hits %d want %q hits %d", step.line, got, hits.Load(), step.want, step.hits)
		}
	}
}

func TestUnknownNotCachedAndCacheBounded(t *testing.T) {
	r := newResolver(true)
	r.store("k", "unknown timeout")
	if _, ok := r.cached("k"); ok {
		t.Fatal("unknown must not be cached")
	}
	for i := 0; i <= maxCache; i++ {
		r.store(fmt.Sprint(i), "ok")
	}
	if len(r.cache) > maxCache {
		t.Fatalf("cache grew to %d", len(r.cache))
	}
}

func TestConcurrencyCap(t *testing.T) {
	release := make(chan struct{})
	r := newTestResolver(t, true, func(w http.ResponseWriter, q *http.Request) {
		<-release
		fmt.Fprint(w, `{"names":{}}`)
	})
	r.sem = make(chan struct{}, 1)
	r.queue = 1
	var wg sync.WaitGroup
	for _, n := range []string{"a", "b"} {
		wg.Add(1)
		go func(n string) { defer wg.Done(); r.handle("check " + n + "@example.com " + pub) }(n)
	}
	for deadline := time.Now().Add(5 * time.Second); r.pending.Load() != 2; time.Sleep(time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("requests never queued")
		}
	}
	if got := r.handle("check c@example.com " + pub); got != "unknown busy" {
		t.Fatalf("got %q", got)
	}
	close(release)
	wg.Wait()
}

// dialServe runs serve on one end of a pipe and returns the client end.
func dialServe(t *testing.T, r *resolver) (net.Conn, *bufio.Reader) {
	a, b := net.Pipe()
	go serve(b, r)
	t.Cleanup(func() { a.Close() })
	return a, bufio.NewReader(a)
}

func TestProtocolPipelinedInOrder(t *testing.T) {
	r := newTestResolver(t, true, func(w http.ResponseWriter, q *http.Request) {
		if q.URL.Query().Get("name") == "slow" {
			time.Sleep(50 * time.Millisecond)
		}
		fmt.Fprint(w, `{"names":{"slow":"`+pub+`"}}`)
	})
	c, rd := dialServe(t, r)
	go fmt.Fprint(c, "check slow@example.com "+pub+"\ncheck fast@example.com "+pub+"\nbogus\n")
	for _, want := range []string{"ok\n", "fail no-name\n", "fail bad-request\n"} {
		if got, _ := rd.ReadString('\n'); got != want {
			t.Fatalf("got %q want %q", got, want)
		}
	}
}

func TestProtocolLineLength(t *testing.T) {
	r := newResolver(true)
	c, rd := dialServe(t, r)
	// 511 chars + "\n" = 512: the longest accepted line.
	go fmt.Fprint(c, strings.Repeat("x", 511)+"\n"+strings.Repeat("x", 512)+"\n")
	for _, want := range []string{"fail bad-request\n", "fail line-too-long\n"} {
		if got, _ := rd.ReadString('\n'); got != want {
			t.Fatalf("got %q want %q", got, want)
		}
	}
	if _, err := rd.ReadString('\n'); err == nil {
		t.Fatal("connection must close after an overlong line")
	}
}

func TestListen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "s")
	ln, err := listen(path, "")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", fi.Mode().Perm())
	}
	tcp, err := listen("", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go serveAll(tcp, newResolver(false))
	c, err := net.Dial("tcp", tcp.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprint(c, "nope\n")
	if got, _ := bufio.NewReader(c).ReadString('\n'); got != "fail bad-request\n" {
		t.Fatalf("got %q", got)
	}
	c.Close()
	tcp.Close()
	for _, bad := range []string{"0.0.0.0:9", "10.0.0.1:9", "localhost:9", ""} {
		if _, err := listen("", bad); err == nil {
			t.Errorf("%q must be refused", bad)
		}
	}
}

func TestTruncatedBodyIsUnknown(t *testing.T) {
	r := newTestResolver(t, true, func(w http.ResponseWriter, q *http.Request) {
		w.Header().Set("Content-Length", "100")
		fmt.Fprint(w, `{"names":`) // short write: the client sees an unexpected EOF
	})
	if got := r.handle("check bob@example.com " + pub); got != "unknown network" {
		t.Fatalf("got %q", got)
	}
}

func TestControlRejectsUnparsableAddress(t *testing.T) {
	if newResolver(true).control("tcp", "not-an-addr", nil) == nil {
		t.Fatal("want error")
	}
}

func TestQueueWaitIsBounded(t *testing.T) {
	r := newResolver(true)
	r.sem = make(chan struct{}, 1)
	r.sem <- struct{}{} // the only slot is taken and never released
	r.timeout = 50 * time.Millisecond
	if got := r.handle("check bob@example.com " + pub); got != "unknown busy" {
		t.Fatalf("got %q", got)
	}
}

func TestTimeoutBelowServer(t *testing.T) {
	if r := newResolver(false); r.timeout != 2500*time.Millisecond {
		t.Fatalf("timeout %v", r.timeout)
	}
}

func TestWriteDeadlineClosesStuckReader(t *testing.T) {
	old := writeTimeout
	writeTimeout = 50 * time.Millisecond
	defer func() { writeTimeout = old }()
	c, rd := dialServe(t, newResolver(true))
	fmt.Fprint(c, "bogus\n") // the reply is not read in time
	time.Sleep(200 * time.Millisecond)
	if _, err := rd.ReadString('\n'); err == nil {
		t.Fatal("serve must close a connection whose peer stops reading")
	}
}

func TestConnectionCap(t *testing.T) {
	old := maxConns
	maxConns = 1
	defer func() { maxConns = old }()
	ln, err := listen("", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go serveAll(ln, newResolver(true))
	first, _ := net.Dial("tcp", ln.Addr().String())
	second, _ := net.Dial("tcp", ln.Addr().String())
	defer second.Close()
	fmt.Fprint(first, "x\n")
	bufio.NewReader(first).ReadString('\n') // first holds the only slot
	fmt.Fprint(second, "x\n")
	rd := bufio.NewReader(second)
	second.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	if _, err := rd.ReadString('\n'); err == nil {
		t.Fatal("second connection served past the cap")
	}
	first.Close()
	second.SetReadDeadline(time.Now().Add(5 * time.Second))
	if got, _ := rd.ReadString('\n'); got != "fail bad-request\n" {
		t.Fatalf("got %q after the first closed", got)
	}
}

func TestListenUnixStaleAndBoth(t *testing.T) {
	path := filepath.Join(t.TempDir(), "s")
	stale, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	stale.(*net.UnixListener).SetUnlinkOnClose(false)
	stale.Close()
	ln, err := listen(path, "")
	if err != nil {
		t.Fatalf("stale socket not replaced: %v", err)
	}
	ln.Close()
	file := filepath.Join(t.TempDir(), "f")
	os.WriteFile(file, nil, 0o600)
	if _, err := listen(file, ""); err == nil {
		t.Fatal("a regular file must not be removed")
	}
	if _, err := listen(path, "127.0.0.1:0"); err == nil {
		t.Fatal("-unix and -tcp together must be refused")
	}
}
