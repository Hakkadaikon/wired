// Package moqtclient is the session setup and varint/control-message
// plumbing shared by the guide's MoQT sample clients, written against
// draft-ietf-moq-transport-22 (negotiated as the WebTransport subprotocol
// "moqt-22"). moqt-hub keeps its own short copy of the handshake because it
// is the introductory page, and moqt-delivery (no hub, so no SETUP) calls
// DialWT; every other sample calls Dial.
package moqtclient

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"log"
	"math/bits"
	"net/http"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/webtransport-go"
)

// Protocol is the WebTransport subprotocol that selects draft-22 (SS6.2).
const Protocol = "moqt-22"

// Session is one MoQT session: a WebTransport session plus both control
// streams (SS6.3), with the server's SETUP already read.
type Session struct {
	*webtransport.Session
	Conn         *quic.Conn    // closing it is how this peer leaves
	Status       int           // the HTTP status of the CONNECT
	Control      *bufio.Reader // the server's control stream, after SETUP
	SetupType    uint64        // 0x2F00
	SetupOptions []byte        // the server's Setup Options, undecoded
	// Our control stream. It is never closed: closing a control stream
	// ends the session as a PROTOCOL_VIOLATION (SS6.3).
	control *webtransport.SendStream
}

// DialWT opens a WebTransport session to url offering the subprotocol
// "moqt-22" (SS6.2.1) and fails unless the server picked it. The QUIC
// connection is returned so the caller can close it.
func DialWT(ctx context.Context, url string) (*webtransport.Session, *quic.Conn, int) {
	var conn *quic.Conn
	d := webtransport.Transport{
		TLSClientConfig:      &tls.Config{InsecureSkipVerify: true}, // self-signed demo cert
		QUICConfig:           &quic.Config{EnableDatagrams: true, EnableStreamResetPartialDelivery: true},
		ApplicationProtocols: []string{Protocol},
		DialAddr: func(ctx context.Context, addr string, t *tls.Config, q *quic.Config) (*quic.Conn, error) {
			c, err := quic.DialAddrEarly(ctx, addr, t, q)
			conn = c
			return c, err
		},
	}
	rsp, s, err := d.Dial(ctx, url, http.Header{})
	Check(err)
	if p := s.SessionState().ApplicationProtocol; p != Protocol {
		log.Fatalf("server picked subprotocol %q, not %q", p, Protocol)
	}
	return s, conn, rsp.StatusCode
}

// Dial opens a MoQT session to url (SS6.3): each side opens one uni
// control stream that starts with SETUP (Type 0x2F00, which is also the
// stream type, SS6.4.1 and SS9.1). Ours carries no Setup Options. The
// server's is the first uni stream it opens, so it is taken here, before
// any data stream.
func Dial(ctx context.Context, url string) *Session {
	s, conn, status := DialWT(ctx, url)
	ctl, err := s.OpenUniStreamSync(ctx)
	Check(err)
	_, err = ctl.Write([]byte{0xAF, 0x00, 0, 0}) // SETUP, Length 0
	Check(err)
	srv, err := s.AcceptUniStream(ctx)
	Check(err)
	r := bufio.NewReader(srv)
	typ, opts := ReadMsg(r)
	if typ != 0x2F00 {
		log.Fatalf("server control stream starts with type %#x, not SETUP", typ)
	}
	return &Session{Session: s, Conn: conn, Status: status, Control: r,
		SetupType: typ, SetupOptions: opts, control: ctl}
}

// Request opens a fresh bidi request stream (SS6.4.2), sends one request
// message on it and returns the stream and a reader for the server's
// answers, which come back on the same stream. Leaving the stream open
// keeps the request alive; resetting it would cancel the request.
func (s *Session) Request(ctx context.Context, typ byte, body []byte) (*webtransport.Stream, *bufio.Reader) {
	st, err := s.OpenStreamSync(ctx)
	Check(err)
	WriteMsg(st, typ, body)
	return st, bufio.NewReader(st)
}

// Varint reads a MoQT variable-length integer: the count of leading 1 bits
// in the first byte is the count of bytes that follow.
func Varint(r *bufio.Reader) uint64 {
	b, err := r.ReadByte()
	Check(err)
	n := bits.LeadingZeros8(^b)
	v := uint64(b) & (0xff >> (n + 1))
	for ; n > 0; n-- {
		c, err := r.ReadByte()
		Check(err)
		v = v<<8 | uint64(c)
	}
	return v
}

// ReadMsg reads one control message: Type (varint), 16-bit Length, body.
func ReadMsg(r *bufio.Reader) (uint64, []byte) {
	typ := Varint(r)
	var hdr [2]byte
	_, err := io.ReadFull(r, hdr[:])
	Check(err)
	body := make([]byte, int(hdr[0])<<8|int(hdr[1]))
	_, err = io.ReadFull(r, body)
	Check(err)
	return typ, body
}

// WriteMsg writes one control message: Type, 16-bit Length, body. The
// Type must fit a one-byte varint (below 128).
func WriteMsg(w io.Writer, typ byte, body []byte) {
	_, err := w.Write(append([]byte{typ, byte(len(body) >> 8), byte(len(body))}, body...))
	Check(err)
}

// Str appends a length-prefixed string (shorter than 128 bytes, so its
// length fits a one-byte varint).
func Str(b []byte, s string) []byte {
	return append(append(b, byte(len(s))), s...)
}

// Check fails the client loudly; every sample's request/decode path is
// expected to succeed, so there is nothing a sample can usefully recover
// from.
func Check(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

// Track encodes Request ID id, Track Namespace "guide" and Track Name
// name: the common head of SUBSCRIBE, PUBLISH and FETCH (SS9.6, SS9.8,
// SS9.11).
func Track(id byte, name string) []byte {
	return Str(Str([]byte{id, 1}, "guide"), name)
}

// Message Parameters (SS9.20) are a count, then per parameter its Type as
// a delta from the previous Type (starting at 0) and its value. The
// LOCATION_FILTER (0x21, SS9.20.9) value is a Filter Type and its fields,
// with no length prefix.

// JoinBack is the SUBSCRIBE parameter list that joins a track with its
// last n Groups, the current one included (SS3.5): LOCATION_FILTER Next
// Object (0x05) for the live part, plus FILL_PARAMETERS (0x23, SS9.20.15:
// Type delta 2 from 0x21, then the length-prefixed inner list) whose
// LOCATION_FILTER Relative Start (0x01) n asks for Groups
// Largest.Group+1-n up to the Largest Object on a fill fetch stream
// (SS3.4).
func JoinBack(n byte) []byte {
	return []byte{2, 0x21, 0x05, 0x23 - 0x21, 4, 1, 0x21, 0x01, n}
}

// Subscribe sends SUBSCRIBE (type 0x3, SS9.6) for guide/name on a request
// stream of its own, with params (an encoded parameter list; none when
// empty), and returns the reply plus that stream's reader, where
// PUBLISH_DONE arrives later.
func (s *Session) Subscribe(ctx context.Context, id byte, name string, params ...byte) (SubscribeReply, *bufio.Reader) {
	if len(params) == 0 {
		params = []byte{0}
	}
	_, r := s.Request(ctx, 0x3, append(Track(id, name), params...))
	return ReadSubscribeReply(r), r
}

// SubscribeReply is the decoded outcome of one SUBSCRIBE: Ok and Alias
// on SUBSCRIBE_OK (SS9.7), plus its LARGEST_OBJECT parameter (0x09,
// SS9.20.17) when the track has one; !Ok and ErrCode on REQUEST_ERROR
// (SS9.4).
type SubscribeReply struct {
	Ok                          bool
	Alias                       uint64
	HasLargest                  bool
	LargestGroup, LargestObject uint64
	ErrCode                     uint64
}

// ReadSubscribeReply reads the server's one reply to a SUBSCRIBE.
func ReadSubscribeReply(r *bufio.Reader) SubscribeReply {
	typ, body := ReadMsg(r)
	br := bufio.NewReader(bytes.NewReader(body))
	switch typ {
	case 0x4: // SUBSCRIBE_OK: Track Alias, then parameters
		// The hub sends at most one parameter here, LARGEST_OBJECT, so
		// only a first parameter is looked at: skipping an unknown one
		// would need its type-specific encoding.
		reply := SubscribeReply{Ok: true, Alias: Varint(br)}
		if Varint(br) > 0 && Varint(br) == 0x09 {
			reply.HasLargest = true
			reply.LargestGroup, reply.LargestObject = Varint(br), Varint(br)
		}
		return reply
	case 0x5: // REQUEST_ERROR
		return SubscribeReply{ErrCode: Varint(br)}
	default:
		log.Fatalf("unexpected control message type %#x", typ)
		return SubscribeReply{}
	}
}

// ReadObject decodes one Object from a uni stream: a SUBGROUP_HEADER
// (SS11.3.1: Type, Track Alias, Group ID) followed by Object ID delta,
// payload length, payload.
func ReadObject(r *bufio.Reader) (alias, group uint64, payload []byte) {
	// Type (the samples' publishers and the hub send 0x70: FIRST_OBJECT
	// (0x40) set, no Subgroup ID field, default priority, no properties).
	Varint(r)
	alias = Varint(r)
	group = Varint(r)
	Varint(r) // Object ID delta
	payload = make([]byte, Varint(r))
	_, err := io.ReadFull(r, payload)
	Check(err)
	return
}

// Fetch is the body of a FETCH (type 0x16, SS9.11) for guide/name:
// Groups startGroup through endGroup, whole. The range is a
// LOCATION_FILTER of type 0x03 (Absolute Start, Group End): Start
// {startGroup, 0}, End Group Delta endGroup-startGroup. Every value fits
// a one-byte varint.
func Fetch(id byte, name string, startGroup, endGroup byte) []byte {
	return append(Track(id, name), 1, 0x21, 0x03, startGroup, 0, endGroup-startGroup)
}

// ReadFetchOk reads FETCH_OK (type 0x18, SS9.12) and returns its End
// Location, which is inclusive: the last Location the fetch covers. Any
// other reply fails the client.
func ReadFetchOk(r *bufio.Reader) (endGroup, endObject uint64) {
	typ, body := ReadMsg(r)
	if typ != 0x18 {
		log.Fatalf("FETCH answered with type %#x, not FETCH_OK", typ)
	}
	br := bufio.NewReader(bytes.NewReader(body))
	_, err := br.ReadByte() // End Of Track
	Check(err)
	return Varint(br), Varint(br)
}

// FetchItem is one entry of a fetch data stream: an Object, or an End of
// Range whose last Location is Group/Object -- Unknown (0x10C) or
// TimedOut (0x20C); neither flag is an End of Non-Existent Range (0x8C).
type FetchItem struct {
	Range, Unknown, TimedOut bool
	Group, Object            uint64
	Payload                  []byte
}

// ReadFetch reads a fetch data stream to its FIN (SS11.4.1): FETCH_HEADER
// (type 0x5, Request ID), then fetch Objects whose Serialization Flags
// say which fields follow. Groups are taken as ascending. A FETCH's
// stream carries the FETCH's Request ID, a fill's the SUBSCRIBE's.
func ReadFetch(r *bufio.Reader) (requestID uint64, items []FetchItem) {
	if t := Varint(r); t != 0x5 {
		log.Fatalf("stream type %#x is not FETCH_HEADER", t)
	}
	requestID = Varint(r)
	var g, o uint64
	for first := true; ; first = false {
		if _, err := r.Peek(1); err == io.EOF {
			return
		}
		flags := Varint(r)
		// End of Range (SS11.4.1.2): an absolute Location, no payload.
		if flags == 0x8C || flags == 0x10C || flags == 0x20C {
			g, o = Varint(r), Varint(r)
			items = append(items, FetchItem{Range: true, Unknown: flags == 0x10C,
				TimedOut: flags == 0x20C, Group: g, Object: o})
			continue
		}
		newGroup := flags&0x08 != 0
		if newGroup && first {
			g = Varint(r) // the first Object's deltas are absolute
		} else if newGroup {
			g += Varint(r) + 1
		}
		if flags&0x40 == 0 && flags&0x03 == 0x03 {
			Varint(r) // explicit Subgroup ID
		}
		switch {
		case flags&0x04 == 0:
			o++
		case newGroup || first:
			o = Varint(r)
		default:
			o += Varint(r)
		}
		if flags&0x10 != 0 {
			_, err := r.ReadByte() // Publisher Priority
			Check(err)
		}
		if flags&0x20 != 0 {
			_, err := r.Discard(int(Varint(r))) // Object Properties
			Check(err)
		}
		payload := make([]byte, Varint(r))
		_, err := io.ReadFull(r, payload)
		Check(err)
		items = append(items, FetchItem{Group: g, Object: o, Payload: payload})
	}
}

// Namespace encodes a Track Namespace (SS8.7): the field count, then each
// field length-prefixed. Every count and field here is shorter than 128,
// so each fits a one-byte varint.
func Namespace(fields ...string) []byte {
	b := []byte{byte(len(fields))}
	for _, f := range fields {
		b = Str(b, f)
	}
	return b
}

// ReadNamespace decodes the Track Namespace (Suffix) that is the whole
// body of a NAMESPACE / NAMESPACE_DONE (SS9.16, SS9.17).
func ReadNamespace(body []byte) []string {
	r := bufio.NewReader(bytes.NewReader(body))
	fields := make([]string, Varint(r))
	for i := range fields {
		f := make([]byte, Varint(r))
		_, err := io.ReadFull(r, f)
		Check(err)
		fields[i] = string(f)
	}
	return fields
}
