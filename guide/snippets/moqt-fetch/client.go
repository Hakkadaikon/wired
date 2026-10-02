package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/webtransport-go"

	"wired-guide/moqtclient"
)

// dial opens one WebTransport session to the hub (one MoQT peer); the
// QUIC connection is returned so main can close it before exiting.
func dial(ctx context.Context, url string) (*webtransport.Session, *quic.Conn) {
	var conn *quic.Conn
	d := webtransport.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		QUICConfig:      &quic.Config{EnableDatagrams: true, EnableStreamResetPartialDelivery: true},
		DialAddr: func(ctx context.Context, addr string, t *tls.Config, c *quic.Config) (*quic.Conn, error) {
			var err error
			conn, err = quic.DialAddrEarly(ctx, addr, t, c)
			return conn, err
		},
	}
	_, s, err := d.Dial(ctx, url+"/moqt", http.Header{})
	moqtclient.Check(err)
	return s, conn
}

// request opens a fresh bidi request stream (draft-ietf-moq-transport-19
// SS3.3), lets send write the request on it, and returns a reader for the
// hub's answer.
func request(ctx context.Context, s *webtransport.Session, send func(io.Writer)) *bufio.Reader {
	st, err := s.OpenStreamSync(ctx)
	moqtclient.Check(err)
	send(st)
	return bufio.NewReader(st)
}

// msg is a send for request: one control message.
func msg(typ byte, body []byte) func(io.Writer) {
	return func(w io.Writer) { moqtclient.WriteMsg(w, typ, body) }
}

// publishGroup sends Group g of track alias 1 as one Object on its own
// uni stream: SUBGROUP_HEADER (Type 0x30: Subgroup 0, default priority,
// no properties), Object ID delta 0, length, "frame-g".
func publishGroup(ctx context.Context, s *webtransport.Session, g byte) {
	st, err := s.OpenUniStreamSync(ctx)
	moqtclient.Check(err)
	_, err = st.Write(append([]byte{0x30, 1, g, 0, 7}, fmt.Sprintf("frame-%d", g)...))
	moqtclient.Check(err)
	moqtclient.Check(st.Close())
}

// waitIngested returns once the hub holds Group g. A standalone FETCH of
// Group g is answered REQUEST_ERROR INVALID_RANGE (0x5) while g is past
// the track's Largest Object (draft-ietf-moq-transport-19 SS10.12.3), and
// FETCH_OK (0x18) once it is not, so it is retried every 100 ms, up to
// 3 s. Request IDs 2, 4, ... follow the PUBLISH's 0 (each fits one byte).
func waitIngested(ctx context.Context, s *webtransport.Session, g byte) {
	for id := byte(2); id < 62; id += 2 {
		st, err := s.OpenStreamSync(ctx)
		moqtclient.Check(err)
		moqtclient.StandaloneFetch(st, id, "clock", g, g)
		// Our side of this request is done: closing it frees the stream,
		// so the retries never run out of stream credit.
		moqtclient.Check(st.Close())
		typ, _ := moqtclient.ReadMsg(bufio.NewReader(st))
		if typ == 0x18 {
			uni, err := s.AcceptUniStream(ctx) // drain this FETCH's Objects
			moqtclient.Check(err)
			moqtclient.ReadFetch(bufio.NewReader(uni))
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	log.Fatalf("the hub never took in Group %d", g)
}

// printFetch prints every item of the next fetch data stream and returns
// the last one.
func printFetch(ctx context.Context, s *webtransport.Session, label string) moqtclient.FetchItem {
	uni, err := s.AcceptUniStream(ctx)
	moqtclient.Check(err)
	rid, items := moqtclient.ReadFetch(bufio.NewReader(uni))
	for _, it := range items {
		if it.Unknown {
			fmt.Printf("%s (request %d): end of unknown range up to %d/%d\n", label, rid, it.Group, it.Object)
		} else {
			fmt.Printf("%s (request %d): %d/%d %q\n", label, rid, it.Group, it.Object, it.Payload)
		}
	}
	return items[len(items)-1]
}

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	// The publisher: PUBLISH guide/clock (Request ID 0, Track Alias 1),
	// answered by REQUEST_OK (0x7), then Groups 0..5. The hub caches them
	// in its 4-Object arena, so Groups 0 and 1 are evicted.
	pub, pubConn := dial(ctx, os.Args[1])
	defer pubConn.CloseWithError(0, "")
	r := request(ctx, pub, msg(0x1D, append(moqtclient.Str(moqtclient.Str([]byte{0, 1}, "guide"), "clock"), 1, 0)))
	if typ, _ := moqtclient.ReadMsg(r); typ != 0x7 {
		log.Fatalf("PUBLISH answered with type %#x", typ)
	}
	for g := byte(0); g < 6; g++ {
		publishGroup(ctx, pub, g)
	}
	// The publisher asks the hub itself whether Group 5 has arrived, so
	// the viewer below joins at a known Largest Object.
	waitIngested(ctx, pub, 5)

	// (1) The viewer joins late: SUBSCRIBE with LOCATION_FILTER (0x21) =
	// Largest Object (0x2) -- only Objects after the current Largest come
	// live. SUBSCRIBE_OK's LARGEST_OBJECT (0x09) is the Joining Location.
	view, viewConn := dial(ctx, os.Args[1])
	defer viewConn.CloseWithError(0, "")
	sub := append(moqtclient.Str(moqtclient.Str([]byte{0, 1}, "guide"), "clock"), 1, 0x21, 1, 0x2)
	typ, body := moqtclient.ReadMsg(request(ctx, view, msg(0x3, sub)))
	br := bufio.NewReader(bytes.NewReader(body))
	if typ != 0x4 {
		log.Fatalf("SUBSCRIBE answered with type %#x", typ)
	}
	moqtclient.Varint(br) // Track Alias
	if moqtclient.Varint(br) != 1 || moqtclient.Varint(br) != 0x09 {
		log.Fatal("SUBSCRIBE_OK carries no LARGEST_OBJECT")
	}
	fmt.Printf("subscribe (request 0): joining location %d/%d\n", moqtclient.Varint(br), moqtclient.Varint(br))

	// (2) A standalone FETCH (Request ID 2) of Groups 0..2: FETCH_OK on the
	// request stream, the Objects on a uni stream of their own. The
	// evicted Groups 0 and 1 come back as one End of Unknown Range.
	r = request(ctx, view, func(w io.Writer) { moqtclient.StandaloneFetch(w, 2, "clock", 0, 2) })
	eg, eo := moqtclient.ReadFetchOk(r)
	fmt.Printf("standalone fetch (request 2): FETCH_OK end %d/%d\n", eg, eo)
	printFetch(ctx, view, "standalone fetch")

	// (3) A Relative Joining FETCH (Request ID 4) tied to the subscription:
	// the 2 Groups before the Joining Location, ending right at it.
	r = request(ctx, view, func(w io.Writer) { moqtclient.JoiningFetch(w, 4, 0, 2) })
	eg, eo = moqtclient.ReadFetchOk(r)
	fmt.Printf("joining fetch (request 4): FETCH_OK end %d/%d\n", eg, eo)
	last := printFetch(ctx, view, "joining fetch")

	// The publisher moves on: Groups 6 and 7 reach the viewer live, each on
	// its own uni stream (one at a time here, since separate streams may
	// arrive in either order).
	var firstLive uint64
	for g := byte(6); g < 8; g++ {
		publishGroup(ctx, pub, g)
		uni, err := view.AcceptUniStream(ctx)
		moqtclient.Check(err)
		_, group, payload := moqtclient.ReadObject(bufio.NewReader(uni))
		fmt.Printf("subscription: %d/0 %q\n", group, payload)
		if g == 6 {
			firstLive = group
		}
	}

	// One Object per Group, so the join is seamless when the first live
	// Group is the one right after the joining fetch's last.
	fmt.Printf("join point: fetch ends at %d/%d, live starts at %d/0, seamless=%v\n",
		last.Group, last.Object, firstLive, firstLive == last.Group+1)
}
