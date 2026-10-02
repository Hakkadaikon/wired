// Package moqtclient is the varint/control-message plumbing shared by the
// guide's MoQT sample clients. moqt-hub and moqt-publish grew this code
// independently before there was a third client that needed it; moqt-live
// and moqt-authorize are that third (and fourth) copy, so it moved here
// (see guide-common.md's ruling: the helper package is created by the
// first sample that actually needs it, not kept speculative up front).
package moqtclient

import (
	"bufio"
	"bytes"
	"io"
	"log"
	"math/bits"
)

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

// Str appends a length-prefixed string (shorter than 128 bytes, so its
// length fits a one-byte varint).
func Str(b []byte, s string) []byte {
	return append(append(b, byte(len(s))), s...)
}

// Check fails the client loudly; every sample's SUBSCRIBE/decode path is
// expected to succeed, so there is nothing a sample can usefully recover
// from.
func Check(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

// Subscribe writes a SUBSCRIBE (type 0x3) for Track Namespace "guide",
// Track Name name, with the given Request ID (fits a one-byte varint).
func Subscribe(ctl io.Writer, id byte, name string) {
	sub := append(Str(Str([]byte{id, 1}, "guide"), name), 0)
	_, err := ctl.Write(append([]byte{0x3, 0, byte(len(sub))}, sub...))
	Check(err)
}

// SubscribeReply is the decoded outcome of one SUBSCRIBE (draft-ietf-moq-
// transport-19 SS10.8): Ok and Alias on SUBSCRIBE_OK, !Ok and ErrCode on
// REQUEST_ERROR.
type SubscribeReply struct {
	Ok      bool
	Alias   uint64
	ErrCode uint64
}

// ReadSubscribeReply reads the server's one reply to a SUBSCRIBE.
func ReadSubscribeReply(r *bufio.Reader) SubscribeReply {
	typ, body := ReadMsg(r)
	br := bufio.NewReader(bytes.NewReader(body))
	switch typ {
	case 0x4: // SUBSCRIBE_OK
		return SubscribeReply{Ok: true, Alias: Varint(br)}
	case 0x5: // REQUEST_ERROR
		return SubscribeReply{ErrCode: Varint(br)}
	default:
		log.Fatalf("unexpected control message type %#x", typ)
		return SubscribeReply{}
	}
}

// ReadObject decodes one Object from a uni stream: a SUBGROUP_HEADER
// (Type, Track Alias, Group ID) followed by Object ID delta, payload
// length, payload.
func ReadObject(r *bufio.Reader) (alias, group uint64, payload []byte) {
	Varint(r) // Type 0x70: no Subgroup ID, default priority, no properties
	alias = Varint(r)
	group = Varint(r)
	Varint(r) // Object ID delta
	payload = make([]byte, Varint(r))
	_, err := io.ReadFull(r, payload)
	Check(err)
	return
}

// WriteMsg writes one control message: Type, 16-bit Length, body. The
// Type must fit a one-byte varint (below 64).
func WriteMsg(w io.Writer, typ byte, body []byte) {
	_, err := w.Write(append([]byte{typ, byte(len(body) >> 8), byte(len(body))}, body...))
	Check(err)
}

// StandaloneFetch writes a FETCH (type 0x16, Fetch Type 0x1, draft-ietf-
// moq-transport-19 SS10.12.1) for Track Namespace "guide", Track Name
// name: groups startGroup through endGroup (End Location {endGroup, 0}
// means the whole End group). Every value fits a one-byte varint.
func StandaloneFetch(w io.Writer, id byte, name string, startGroup, endGroup byte) {
	body := append(Str(Str([]byte{id, 0x1, 1}, "guide"), name), startGroup, 0, endGroup, 0, 0)
	WriteMsg(w, 0x16, body)
}

// JoiningFetch writes a Relative Joining FETCH (Fetch Type 0x2,
// SS10.12.2): from joiningStart groups before the Joining Location of the
// subscription with Request ID subID, up to that Location.
func JoiningFetch(w io.Writer, id, subID, joiningStart byte) {
	WriteMsg(w, 0x16, []byte{id, 0x2, subID, joiningStart, 0})
}

// ReadFetchOk reads FETCH_OK (type 0x18, SS10.13) and returns its End
// Location; any other reply fails the client.
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

// FetchItem is one entry of a fetch data stream: an Object, or (Unknown)
// an End of Unknown Range whose last Location is Group/Object.
type FetchItem struct {
	Unknown       bool
	Group, Object uint64
	Payload       []byte
}

// ReadFetch reads a fetch data stream to its FIN (SS11.4.4): FETCH_HEADER
// (type 0x5, Request ID), then fetch Objects whose Serialization Flags
// say which fields follow. Groups are taken as ascending.
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
		// End of Range (SS11.4.4.2): an absolute Location, no payload.
		if flags == 0x8C || flags == 0x10C {
			g, o = Varint(r), Varint(r)
			items = append(items, FetchItem{Unknown: flags == 0x10C, Group: g, Object: o})
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
