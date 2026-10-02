package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
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
// SS3.3), sends one control message on it and returns the hub's first
// answer plus a reader for whatever follows on the stream. The stream is
// never closed from this side: that keeps the request open.
func request(ctx context.Context, s *webtransport.Session, typ byte, body []byte) (uint64, *bufio.Reader, *bufio.Reader) {
	st, err := s.OpenStreamSync(ctx)
	moqtclient.Check(err)
	moqtclient.WriteMsg(st, typ, body)
	r := bufio.NewReader(st)
	t, reply := moqtclient.ReadMsg(r)
	return t, bufio.NewReader(bytes.NewReader(reply)), r
}

// publish announces track guide/name with Track Alias alias: PUBLISH
// (0x1D), answered REQUEST_OK (0x7).
func publish(ctx context.Context, s *webtransport.Session, id byte, name string, alias byte) {
	body := append(moqtclient.Str(moqtclient.Str([]byte{id, 1}, "guide"), name), alias, 0)
	if t, _, _ := request(ctx, s, 0x1D, body); t != 0x7 {
		log.Fatalf("PUBLISH %s answered with type %#x", name, t)
	}
}

// subscribe sends SUBSCRIBE (0x3) for guide/name with one parameter,
// SUBSCRIBER_PRIORITY (0x20, a single byte: lower is more important), and
// returns the request stream, on which PUBLISH_DONE arrives later.
func subscribe(ctx context.Context, s *webtransport.Session, id byte, name string, prio byte) *bufio.Reader {
	body := append(moqtclient.Str(moqtclient.Str([]byte{id, 1}, "guide"), name), 1, 0x20, prio)
	t, _, r := request(ctx, s, 0x3, body)
	if t != 0x4 {
		log.Fatalf("SUBSCRIBE %s answered with type %#x", name, t)
	}
	fmt.Printf("subscriber: SUBSCRIBE %s priority=%d -> SUBSCRIBE_OK\n", name, prio)
	return r
}

// sendGroup starts Group 0 of track alias on a uni stream and leaves the
// stream open, the way a live encoder keeps writing: SUBGROUP_HEADER
// (Type 0x30: Subgroup 0, default Publisher Priority), Object ID delta 0,
// length, payload.
func sendGroup(ctx context.Context, s *webtransport.Session, alias byte, payload string) {
	st, err := s.OpenUniStreamSync(ctx)
	moqtclient.Check(err)
	_, err = st.Write(append([]byte{0x30, alias, 0, 0, byte(len(payload))}, payload...))
	moqtclient.Check(err)
}

// receive accepts the subscriber's relay stream and prints its first
// Object; the stream stays open and is returned.
func receive(ctx context.Context, s *webtransport.Session, name string) *bufio.Reader {
	uni, err := s.AcceptUniStream(ctx)
	moqtclient.Check(err)
	r := bufio.NewReader(uni)
	_, group, payload := moqtclient.ReadObject(r)
	fmt.Printf("subscriber: %s group %d %q\n", name, group, payload)
	return r
}

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	// The publisher announces two tracks.
	pub, pubConn := dial(ctx, os.Args[1])
	defer pubConn.CloseWithError(0, "")
	publish(ctx, pub, 0, "video", 1)
	publish(ctx, pub, 2, "audio", 2)

	// The subscriber reads SETUP on the control stream the hub opened; the
	// hub's GOAWAY arrives on the same stream later.
	sub, subConn := dial(ctx, os.Args[1])
	defer subConn.CloseWithError(0, "")
	ctlStream, err := sub.AcceptStream(ctx)
	moqtclient.Check(err)
	ctl := bufio.NewReader(ctlStream)
	moqtclient.ReadMsg(ctl) // SETUP

	// Audio matters more than video here: priority 10 against 200. The
	// server log shows the urgency the hub gave each relay stream.
	videoReq := subscribe(ctx, sub, 0, "video", 200)
	audioReq := subscribe(ctx, sub, 2, "audio", 10)
	sendGroup(ctx, pub, 1, "keyframe")
	video := receive(ctx, sub, "video")
	sendGroup(ctx, pub, 2, "frame")
	audio := receive(ctx, sub, "audio")

	// Ask the server to drain (this demo's trigger is any datagram).
	moqtclient.Check(sub.SendDatagram([]byte("drain")))
	typ, body := moqtclient.ReadMsg(ctl)
	if typ != 0x10 {
		log.Fatalf("expected GOAWAY, got type %#x", typ)
	}
	br := bufio.NewReader(bytes.NewReader(body))
	uri := make([]byte, moqtclient.Varint(br))
	_, err = io.ReadFull(br, uri)
	moqtclient.Check(err)
	fmt.Printf("subscriber: GOAWAY new_uri=%s timeout=%dms\n", uri, moqtclient.Varint(br))

	// After GOAWAY every new request is refused: REQUEST_ERROR (0x5)
	// GOING_AWAY (0x6). A client would open its next request on new_uri.
	body = append(moqtclient.Str(moqtclient.Str([]byte{4, 1}, "guide"), "video"), 0)
	if t, reply, _ := request(ctx, sub, 0x3, body); t == 0x5 {
		fmt.Printf("subscriber: new SUBSCRIBE -> REQUEST_ERROR error_code=%d\n", moqtclient.Varint(reply))
	} else {
		log.Fatalf("new SUBSCRIBE answered with type %#x", t)
	}

	// The subscriptions already granted keep flowing until the timeout.
	// Then the hub resets their relay streams and ends each with
	// PUBLISH_DONE (0xB) GOING_AWAY (0x4) on its request stream.
	for _, st := range []struct {
		name      string
		relay, rq *bufio.Reader
	}{{"video", video, videoReq}, {"audio", audio, audioReq}} {
		_, err := st.relay.ReadByte()
		var se *webtransport.StreamError
		if !errors.As(err, &se) {
			log.Fatalf("%s relay stream: %v", st.name, err)
		}
		fmt.Printf("subscriber: %s relay stream reset error_code=%#x\n", st.name, se.ErrorCode)
		typ, body := moqtclient.ReadMsg(st.rq)
		if typ != 0xB {
			log.Fatalf("expected PUBLISH_DONE, got type %#x", typ)
		}
		fmt.Printf("subscriber: %s PUBLISH_DONE status=%d\n", st.name, moqtclient.Varint(bufio.NewReader(bytes.NewReader(body))))
	}

	// On the next tick the hub closes the session: GOAWAY_TIMEOUT (0x10),
	// since this client left its request streams open.
	_, err = sub.AcceptUniStream(ctx)
	var se *webtransport.SessionError
	if !errors.As(err, &se) {
		log.Fatal(err)
	}
	fmt.Printf("subscriber: session closed error_code=%#x\n", se.ErrorCode)
}
