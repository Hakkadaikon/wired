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
