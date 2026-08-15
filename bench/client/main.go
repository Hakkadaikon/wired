// benchclient: per-request latency load client for the comparison doc's
// loopback lane. Two modes:
//   - ttfb: n sequential fresh-connection requests (dial start -> body fully
//     read, QUIC+TLS handshake included).
//   - load: n requests over c concurrent streams on a warmed connection.
//
// Per-request timeout 10s (a timeout counts as a failure and the worker
// moves on); a run aborts after 500 failures. Reports its own CPU time so
// client-saturated runs can be judged.
package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

const perReqTimeout = 10 * time.Second
const maxFails = 500

func cpuMs() float64 {
	var ru syscall.Rusage
	syscall.Getrusage(syscall.RUSAGE_SELF, &ru)
	u := time.Duration(ru.Utime.Sec)*time.Second + time.Duration(ru.Utime.Usec)*time.Microsecond
	s := time.Duration(ru.Stime.Sec)*time.Second + time.Duration(ru.Stime.Usec)*time.Microsecond
	return float64((u + s).Milliseconds())
}

func newClient() *http.Client {
	return &http.Client{Transport: &http3.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		QUICConfig:      &quic.Config{},
	}}
}

func oneRequest(client *http.Client, url string) (time.Duration, error) {
	ctx, cancel := context.WithTimeout(context.Background(), perReqTimeout)
	defer cancel()
	start := time.Now()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if _, err := io.Copy(io.Discard, resp.Body); err != nil {
		return 0, err
	}
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("status %d", resp.StatusCode)
	}
	return time.Since(start), nil
}

func report(mode string, n int, fails int64, lat []time.Duration, wall time.Duration) {
	sort.Slice(lat, func(i, j int) bool { return lat[i] < lat[j] })
	pct := func(p float64) float64 {
		if len(lat) == 0 {
			return 0
		}
		i := int(p * float64(len(lat)-1))
		return float64(lat[i].Microseconds()) / 1000.0
	}
	rps := float64(len(lat)) / wall.Seconds()
	cpu := cpuMs() / float64(wall.Milliseconds()) * 100
	fmt.Printf("mode=%s n=%d fails=%d reqps=%.1f p50=%.2f p99=%.2f cpu%%=%.0f\n",
		mode, n, fails, rps, pct(0.50), pct(0.99), cpu)
}

func runTTFB(url string, n int) {
	var fails int64
	lat := make([]time.Duration, 0, n)
	start := time.Now()
	for i := 0; i < n; i++ {
		client := newClient()
		d, err := oneRequest(client, url)
		client.Transport.(*http3.Transport).Close()
		if err != nil {
			fails++
			if fails >= maxFails {
				break
			}
			continue
		}
		lat = append(lat, d)
	}
	report("ttfb", n, fails, lat, time.Since(start))
}

func runLoad(url string, n, conc int) {
	client := newClient()
	defer client.Transport.(*http3.Transport).Close()
	if _, err := oneRequest(client, url); err != nil { // warm the connection
		fmt.Fprintf(os.Stderr, "warmup failed: %v\n", err)
		os.Exit(1)
	}
	var fails, issued int64
	latCh := make(chan time.Duration, n)
	start := time.Now()
	var wg sync.WaitGroup
	for w := 0; w < conc; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				if atomic.AddInt64(&issued, 1) > int64(n) {
					return
				}
				if atomic.LoadInt64(&fails) >= maxFails {
					return
				}
				d, err := oneRequest(client, url)
				if err != nil {
					atomic.AddInt64(&fails, 1)
					continue
				}
				latCh <- d
			}
		}()
	}
	wg.Wait()
	close(latCh)
	lat := make([]time.Duration, 0, n)
	for d := range latCh {
		lat = append(lat, d)
	}
	report("load", n, fails, lat, time.Since(start))
}

func main() {
	mode := flag.String("mode", "ttfb", "ttfb | load")
	n := flag.Int("n", 100, "request count")
	conc := flag.Int("c", 20, "concurrent streams (load mode)")
	url := flag.String("url", "https://127.0.0.1:14433/1k.bin", "target URL")
	flag.Parse()
	switch *mode {
	case "ttfb":
		runTTFB(*url, *n)
	case "load":
		runLoad(*url, *n, *conc)
	default:
		fmt.Fprintln(os.Stderr, "unknown mode")
		os.Exit(2)
	}
}
