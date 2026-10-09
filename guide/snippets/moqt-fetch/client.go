package main

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"wired-guide/moqtclient"
)

// publishGroup sends Group g of track alias 1 as one Object on its own
// uni stream: SUBGROUP_HEADER (Type 0x70: FIRST_OBJECT -- the Original
// Publisher opening a subgroup MUST set it, SS2.2 -- Subgroup 0, default
// priority, no properties), Object ID delta 0, length, "frame-g".
func publishGroup(ctx context.Context, s *moqtclient.Session, g byte) {
	st, err := s.OpenUniStreamSync(ctx)
	moqtclient.Check(err)
	_, err = st.Write(append([]byte{0x70, 1, g, 0, 7}, fmt.Sprintf("frame-%d", g)...))
	moqtclient.Check(err)
	moqtclient.Check(st.Close())
}

// waitIngested returns once the hub holds Group g. A FETCH of Group g is
// answered REQUEST_ERROR (0x5) INVALID_RANGE (0x11) while g is past the
// track's Largest Object (draft-ietf-moq-transport-22 SS3.2), and
// FETCH_OK (0x18) once it is not, so it is retried every 100 ms, up to
// 3 s.
// Request IDs 2, 4, ... follow the PUBLISH's 0 (each fits one byte).
func waitIngested(ctx context.Context, s *moqtclient.Session, g byte) {
	for id := byte(2); id < 62; id += 2 {
		st, r := s.Request(ctx, 0x16, moqtclient.Fetch(id, "clock", g, g))
		// Our side of this request is done: closing it frees the stream,
		// so the retries never run out of stream credit.
		moqtclient.Check(st.Close())
		typ, _ := moqtclient.ReadMsg(r)
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
func printFetch(ctx context.Context, s *moqtclient.Session, label string) moqtclient.FetchItem {
	uni, err := s.AcceptUniStream(ctx)
	moqtclient.Check(err)
	rid, items := moqtclient.ReadFetch(bufio.NewReader(uni))
	for _, it := range items {
		switch {
		case it.Unknown:
			fmt.Printf("%s (request %d): end of unknown range up to %d/%d\n", label, rid, it.Group, it.Object)
		case it.TimedOut:
			fmt.Printf("%s (request %d): end of timed-out range up to %d/%d\n", label, rid, it.Group, it.Object)
		case it.Range:
			fmt.Printf("%s (request %d): end of non-existent range up to %d/%d\n", label, rid, it.Group, it.Object)
		default:
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
	pub := moqtclient.Dial(ctx, os.Args[1]+"/moqt")
	defer pub.Conn.CloseWithError(0, "")
	_, r := pub.Request(ctx, 0x1D, append(moqtclient.Track(0, "clock"), 1, 0))
	if typ, _ := moqtclient.ReadMsg(r); typ != 0x7 {
		log.Fatalf("PUBLISH answered with type %#x", typ)
	}
	for g := byte(0); g < 6; g++ {
		publishGroup(ctx, pub, g)
	}
	// The publisher asks the hub itself whether Group 5 has arrived, so
	// the viewer below joins at a known Largest Object.
	waitIngested(ctx, pub, 5)

	// (1) The viewer joins late with the last 3 Groups, the current one
	// included: SUBSCRIBE (Request ID 0) with LOCATION_FILTER Next Object
	// for the live part and a FILL_PARAMETERS whose LOCATION_FILTER
	// Relative Start 3 asks for Groups 3..5 (Largest Group + 1 - 3 up to
	// the Largest Object). SUBSCRIBE_OK's LARGEST_OBJECT is that Largest
	// Object; the live part starts after it.
	view := moqtclient.Dial(ctx, os.Args[1]+"/moqt")
	defer view.Conn.CloseWithError(0, "")
	reply, _ := view.Subscribe(ctx, 0, "clock", moqtclient.JoinBack(3)...)
	if !reply.Ok || !reply.HasLargest {
		log.Fatalf("SUBSCRIBE failed: %+v", reply)
	}
	fmt.Printf("subscribe (request 0): largest object %d/%d\n", reply.LargestGroup, reply.LargestObject)

	// The fill arrives on a fetch stream of its own whose FETCH_HEADER
	// carries the SUBSCRIBE's Request ID; there is no FETCH_OK.
	last := printFetch(ctx, view, "fill")

	// (2) A FETCH (Request ID 2) of Groups 0..2: FETCH_OK on the request
	// stream with its inclusive End Location, the Objects on a uni stream
	// of their own. The evicted Groups 0 and 1 come back as one End of
	// Unknown Range.
	_, r = view.Request(ctx, 0x16, moqtclient.Fetch(2, "clock", 0, 2))
	eg, eo := moqtclient.ReadFetchOk(r)
	fmt.Printf("standalone fetch (request 2): FETCH_OK end %d/%d\n", eg, eo)
	printFetch(ctx, view, "standalone fetch")

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
	// Group is the one right after the fill's last.
	fmt.Printf("join point: fill ends at %d/%d, live starts at %d/0, seamless=%v\n",
		last.Group, last.Object, firstLive, firstLive == last.Group+1)
}
