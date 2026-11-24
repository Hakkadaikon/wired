// nip05d is the NIP-05 resolver helper for moqt_chat: the libc-free server
// asks it, one line at a time, whether name@domain maps to a pubkey. See
// README.md for the protocol and the SSRF limits.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unicode/utf8"
)

const (
	maxLine  = 512 // request line including '\n'
	maxBody  = 64 << 10
	posTTL   = time.Hour
	negTTL   = 5 * time.Minute
	maxCache = 4096
)

var (
	writeTimeout = 5 * time.Second // a reply the peer does not read in time closes the connection
	maxConns     = 16
	errForbidden = errors.New("forbidden address")
	v6Global     = netip.MustParsePrefix("2000::/3")
	// IPv4 not covered by the Addr predicates, plus IPv6 inside 2000::/3 that
	// can tunnel to IPv4 (6to4, Teredo) or is documentation.
	denied = []netip.Prefix{
		netip.MustParsePrefix("100.64.0.0/10"), // CGNAT
		netip.MustParsePrefix("0.0.0.0/8"),
		netip.MustParsePrefix("192.0.0.0/24"),
		netip.MustParsePrefix("198.18.0.0/15"),
		netip.MustParsePrefix("240.0.0.0/4"),
		netip.MustParsePrefix("2002::/16"),
		netip.MustParsePrefix("2001::/32"),
		netip.MustParsePrefix("2001:db8::/32"),
	}
)

// forbidden: IPv6 is an allowlist (2000::/3 only, so NAT64, IPv4-mapped and
// -compatible, ULA, site-local and link-local all fail); IPv4 refuses
// loopback, RFC 1918, link-local (incl. 169.254.169.254), multicast,
// unspecified and the denied prefixes. A zoned address never matches a prefix.
func forbidden(ip netip.Addr) bool {
	if ip.Is6() && !v6Global.Contains(ip) || !ip.IsGlobalUnicast() || ip.IsPrivate() {
		return true
	}
	for _, p := range denied {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

type entry struct {
	verdict string
	exp     time.Time
}

type resolver struct {
	allowPrivate bool
	timeout      time.Duration
	sem          chan struct{} // in-flight fetches
	queue        int32         // fetches allowed to wait for a slot
	pending      atomic.Int32
	tr           *http.Transport
	client       *http.Client
	dialAddr     string // tests only: dial this instead of the resolved address
	now          func() time.Time
	mu           sync.Mutex
	cache        map[string]entry
}

func newResolver(allowPrivate bool) *resolver {
	r := &resolver{
		allowPrivate: allowPrivate,
		timeout:      2500 * time.Millisecond, // under the server's 3 s NIP-05 deadline
		sem:          make(chan struct{}, 8),
		queue:        32,
		now:          time.Now,
		cache:        map[string]entry{},
	}
	d := &net.Dialer{Control: r.control}
	r.tr = &http.Transport{
		Proxy: nil, // a proxy would dial an address the filter never sees
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if r.dialAddr != "" {
				addr = r.dialAddr
			}
			return d.DialContext(ctx, network, addr)
		},
		DisableKeepAlives:      true,
		MaxResponseHeaderBytes: 16 << 10,
	}
	r.client = &http.Client{
		Transport:     r.tr,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	return r
}

// control runs on the address actually dialled, after DNS: this is what stops
// DNS rebinding.
func (r *resolver) control(_, address string, _ syscall.RawConn) error {
	ap, err := netip.ParseAddrPort(address)
	if err != nil {
		return err
	}
	if !r.allowPrivate && forbidden(ap.Addr()) {
		return errForbidden
	}
	return nil
}

func validLocal(s string) bool {
	return s != "" && strings.Trim(s, "abcdefghijklmnopqrstuvwxyz0123456789-_.") == ""
}

func validHex(s string) bool {
	return len(s) == 64 && strings.Trim(s, "0123456789abcdef") == ""
}

// validDomain accepts ASCII LDH labels only. shortcut: no IDNA in the Go
// stdlib, so a U-label is refused; the client must send the punycode A-label.
func validDomain(d string) bool {
	labels := strings.Split(d, ".")
	tld := labels[len(labels)-1]
	if len(d) > 253 || len(labels) < 2 || tld == "" || tld[0] >= '0' && tld[0] <= '9' {
		return false // a digit-led TLD refuses IPv4 literals and forms like 0x7f.1
	}
	for _, l := range labels {
		if len(l) == 0 || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' ||
			strings.Trim(l, "abcdefghijklmnopqrstuvwxyz0123456789-") != "" {
			return false
		}
	}
	return true
}

// handle answers one request line (without '\n').
func (r *resolver) handle(line string) string {
	f := strings.Split(line, " ")
	// non-ASCII first: ToLower folds U+212A KELVIN SIGN to 'k'
	if len(f) != 3 || f[0] != "check" || strings.ContainsFunc(line, func(c rune) bool { return c >= utf8.RuneSelf }) {
		return "fail bad-request"
	}
	name, domain, ok := strings.Cut(strings.ToLower(f[1]), "@")
	if !ok || !validLocal(name) {
		return "fail bad-name"
	}
	if !validDomain(domain) {
		return "fail bad-domain"
	}
	if !validHex(f[2]) {
		return "fail bad-pubkey"
	}
	v := r.check(name, domain, f[2])
	log.Printf("check %s@%s %s -> %s", name, domain, f[2], v)
	return v
}

func (r *resolver) check(name, domain, pub string) string {
	key := name + "@" + domain + " " + pub
	if v, ok := r.cached(key); ok {
		return v
	}
	if r.pending.Add(1) > int32(cap(r.sem))+r.queue {
		r.pending.Add(-1)
		return "unknown busy"
	}
	defer r.pending.Add(-1)
	ctx, cancel := context.WithTimeout(context.Background(), r.timeout) // covers the queue wait too
	defer cancel()
	select {
	case r.sem <- struct{}{}:
	case <-ctx.Done():
		return "unknown busy"
	}
	defer func() { <-r.sem }()
	v := r.fetch(ctx, name, domain, pub)
	r.store(key, v)
	return v
}

func (r *resolver) cached(key string) (string, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	e, ok := r.cache[key]
	if !ok || !r.now().Before(e.exp) {
		return "", false
	}
	return e.verdict, true
}

func (r *resolver) store(key, v string) {
	ttl := negTTL
	switch {
	case v == "ok":
		ttl = posTTL
	case strings.HasPrefix(v, "unknown"):
		return // transient: retry next time
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.cache) >= maxCache {
		r.cache = map[string]entry{} // shortcut: drop all on overflow, LRU if hit rate matters
	}
	r.cache[key] = entry{v, r.now().Add(ttl)}
}

func (r *resolver) fetch(ctx context.Context, name, domain, pub string) string {
	// name and domain are validated to URL-safe characters; no port: 443.
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet,
		"https://"+domain+"/.well-known/nostr.json?name="+name, nil)
	resp, err := r.client.Do(req)
	if err != nil {
		return transportVerdict(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
		return fmt.Sprintf("unknown http-%d", resp.StatusCode) // transient: not cached
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Sprintf("fail http-%d", resp.StatusCode) // 3xx lands here: no redirects
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		return transportVerdict(err)
	}
	if len(body) > maxBody {
		return "fail too-large"
	}
	var doc struct {
		Names map[string]json.RawMessage `json:"names"`
	}
	if json.Unmarshal(body, &doc) != nil {
		return "fail bad-json"
	}
	raw, ok := doc.Names[name]
	if !ok {
		return "fail no-name"
	}
	var v string
	if json.Unmarshal(raw, &v) != nil {
		return "fail bad-json"
	}
	if v != pub {
		return "fail mismatch"
	}
	return "ok"
}

func transportVerdict(err error) string {
	var ne net.Error
	switch {
	case errors.Is(err, errForbidden):
		return "fail forbidden-address"
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &ne) && ne.Timeout():
		return "unknown timeout"
	}
	return "unknown network"
}

// serve answers pipelined requests concurrently, writing replies in order.
func serve(conn net.Conn, r *resolver) {
	defer conn.Close()
	out := make(chan chan string, 64) // also bounds requests in flight per connection
	done := make(chan struct{})
	go func() {
		w := bufio.NewWriter(conn)
		for c := range out {
			conn.SetWriteDeadline(time.Now().Add(writeTimeout))
			w.WriteString(<-c + "\n")
			if len(out) == 0 && w.Flush() != nil {
				conn.Close() // unblocks the reader; later writes fail fast
			}
		}
		w.Flush()
		close(done)
	}()
	sc := bufio.NewScanner(conn)
	sc.Buffer(make([]byte, maxLine), maxLine)
	for sc.Scan() {
		c := make(chan string, 1)
		out <- c
		go func(line string) { c <- r.handle(line) }(sc.Text())
	}
	if errors.Is(sc.Err(), bufio.ErrTooLong) {
		c := make(chan string, 1)
		c <- "fail line-too-long"
		out <- c
	}
	close(out)
	<-done
}

func serveAll(ln net.Listener, r *resolver) error {
	slots := make(chan struct{}, maxConns)
	for {
		slots <- struct{}{} // past the cap, new connections wait in the backlog
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		go func() { serve(c, r); <-slots }()
	}
}

func listen(unixPath, tcpAddr string) (net.Listener, error) {
	if unixPath != "" && tcpAddr != "" {
		return nil, errors.New("give -unix or -tcp, not both")
	}
	if unixPath != "" {
		if fi, err := os.Lstat(unixPath); err == nil && fi.Mode()&os.ModeSocket != 0 {
			os.Remove(unixPath) // stale socket from a previous run
		}
		old := syscall.Umask(0o177) // socket is created 0600
		defer syscall.Umask(old)
		return net.Listen("unix", unixPath)
	}
	ap, err := netip.ParseAddrPort(tcpAddr)
	if err != nil || !ap.Addr().IsLoopback() {
		return nil, fmt.Errorf("-tcp needs a loopback ip:port, got %q", tcpAddr)
	}
	return net.Listen("tcp", tcpAddr)
}

func main() {
	unixPath := flag.String("unix", "", "listen on this Unix socket path (mode 0600)")
	tcpAddr := flag.String("tcp", "", "listen on this loopback ip:port, e.g. 127.0.0.1:4480")
	allowPrivate := flag.Bool("allow-private", false, "e2e fixtures only: allow private/loopback targets")
	flag.Parse()
	if os.Geteuid() == 0 {
		log.Fatal("nip05d: refusing to run as root")
	}
	ln, err := listen(*unixPath, *tcpAddr)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("nip05d: listening on %s (allow-private=%v)", ln.Addr(), *allowPrivate)
	log.Fatal(serveAll(ln, newResolver(*allowPrivate)))
}
