package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"time"

	"github.com/quic-go/webtransport-go"

	"wired-guide/moqtclient"
)

// publish announces track guide/name with Track Alias alias: PUBLISH
// (0x1D), answered REQUEST_OK (0x7) on its request stream.
func publish(ctx context.Context, s *moqtclient.Session, id byte, name string, alias byte) {
	_, r := s.Request(ctx, 0x1D, append(moqtclient.Track(id, name), alias, 0))
	if t, _ := moqtclient.ReadMsg(r); t != 0x7 {
		log.Fatalf("PUBLISH %s answered with type %#x", name, t)
	}
}

// subscribe sends SUBSCRIBE (0x3) for guide/name with one parameter,
// SUBSCRIBER_PRIORITY (0x20, a single byte: lower is more important), and
// returns the request stream, on which PUBLISH_DONE arrives later.
func subscribe(ctx context.Context, s *moqtclient.Session, id byte, name string, prio byte) *bufio.Reader {
	reply, r := s.Subscribe(ctx, id, name, 1, 0x20, prio)
	if !reply.Ok {
		log.Fatalf("SUBSCRIBE %s refused, error_code=%d", name, reply.ErrCode)
	}
	fmt.Printf("subscriber: SUBSCRIBE %s priority=%d -> SUBSCRIBE_OK\n", name, prio)
	return r
}

// sendGroup starts Group 0 of track alias on a uni stream and leaves the
// stream open, the way a live encoder keeps writing: SUBGROUP_HEADER
// (Type 0x70: FIRST_OBJECT, which the Original Publisher opening a
// subgroup MUST set (SS2.2), Subgroup 0, default Publisher Priority),
// Object ID delta 0, length, payload.
func sendGroup(ctx context.Context, s *moqtclient.Session, alias byte, payload string) {
	st, err := s.OpenUniStreamSync(ctx)
	moqtclient.Check(err)
	_, err = st.Write(append([]byte{0x70, alias, 0, 0, byte(len(payload))}, payload...))
	moqtclient.Check(err)
}

// receive accepts the subscriber's relay stream and prints its first
// Object; the stream stays open and is returned.
func receive(ctx context.Context, s *moqtclient.Session, name string) *bufio.Reader {
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
	pub := moqtclient.Dial(ctx, os.Args[1]+"/moqt")
	defer pub.Conn.CloseWithError(0, "")
	publish(ctx, pub, 0, "video", 1)
	publish(ctx, pub, 2, "audio", 2)

	// The subscriber's session. The hub's GOAWAY arrives later on the hub's
	// uni control stream, the one whose SETUP Dial already read.
	sub := moqtclient.Dial(ctx, os.Args[1]+"/moqt")
	defer sub.Conn.CloseWithError(0, "")

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
	typ, body := moqtclient.ReadMsg(sub.Control)
	if typ != 0x10 {
		log.Fatalf("expected GOAWAY, got type %#x", typ)
	}
	br := bufio.NewReader(bytes.NewReader(body))
	uri := make([]byte, moqtclient.Varint(br))
	_, err := io.ReadFull(br, uri)
	moqtclient.Check(err)
	fmt.Printf("subscriber: GOAWAY new_uri=%s timeout=%dms\n", uri, moqtclient.Varint(br))

	// After GOAWAY every new request is refused: REQUEST_ERROR (0x5)
	// GOING_AWAY (0x6). A real client SHOULD NOT start one (SS9.2) and
	// would open its next request on new_uri; this sample sends one on
	// purpose, to show the refusal.
	if reply, _ := sub.Subscribe(ctx, 4, "video"); !reply.Ok {
		fmt.Printf("subscriber: new SUBSCRIBE -> REQUEST_ERROR error_code=%d\n", reply.ErrCode)
	} else {
		log.Fatal("new SUBSCRIBE was accepted after GOAWAY")
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
