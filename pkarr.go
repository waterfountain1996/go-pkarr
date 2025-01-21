// Public-Key Addressable Resource Records
package pkarr

import (
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

const (
	// Maximum allowed length of an encoded DNS packet.
	MaxPacketLength = 1000

	// Signature + uint64 unix timestamp.
	payloadHeaderLength = ed25519.SignatureSize + 8

	// Maximum allowed length of an encoded payload.
	MaxPayloadLength = MaxPacketLength + payloadHeaderLength
)

var (
	// Error that is returned when length of encoded packet is too large.
	ErrPacketTooLarge = errors.New("pkarr: packet is too large")

	// Error that is returned when parsing a malformed Pkarr record.
	ErrInvalidPayload = errors.New("pkarr: invalid payload")
)

// Record represents a signed DNS record.
type Record struct {
	pub ed25519.PublicKey
	sig []byte
	t   time.Time
	m   dnsmessage.Message
	p   []byte // Encoded version on m.
}

// New encodes and signs DNS record m.
// If length of the encoded record is larger than [MaxPacketLength],
// [ErrPacketTooLarge] is returned.
func New(key ed25519.PrivateKey, m dnsmessage.Message, t time.Time) (Record, error) {
	p, err := m.Pack()
	if err != nil {
		return Record{}, fmt.Errorf("pkarr: failed to pack DNS record: %w", err)
	}

	if len(p) > MaxPacketLength {
		return Record{}, ErrPacketTooLarge
	}

	sp := Record{
		pub: key.Public().(ed25519.PublicKey),
		sig: ed25519.Sign(key, signable(t, p)),
		t:   t,
		m:   m,
		p:   p,
	}
	return sp, nil
}

// FromPayload parses a Record in a wire format. Returns [ErrPacketTooLarge] if the payload
// is too large and [ErrInvalidPayload] otherwise.
func FromPayload(pub ed25519.PublicKey, payload []byte) (Record, error) {
	if len(payload) < payloadHeaderLength {
		return Record{}, fmt.Errorf("%w: payload is too small", ErrInvalidPayload)
	} else if len(payload) > MaxPayloadLength {
		return Record{}, ErrPacketTooLarge
	}

	offset := ed25519.SignatureSize
	sig := payload[:offset]

	millis := binary.BigEndian.Uint64(payload[offset:])
	t := time.UnixMilli(int64(millis))

	p := payload[offset+8:]
	var m dnsmessage.Message
	if err := m.Unpack(p); err != nil {
		return Record{}, fmt.Errorf("%w: failed to unpack DNS record: %w", ErrInvalidPayload, err)
	}

	if v := signable(t, p); !ed25519.Verify(pub, v, sig) {
		return Record{}, fmt.Errorf("%w: invalid signature", ErrInvalidPayload)
	}

	sp := Record{
		pub: pub,
		sig: sig,
		t:   t,
		m:   m,
		p:   p,
	}
	return sp, nil
}

// Payload returns an encoded version of Record that is sent over the HTTP relay.
func (sp Record) Payload() []byte {
	buf := make([]byte, ed25519.SignatureSize+8+len(sp.p))
	copy(buf[:ed25519.SignatureSize], sp.sig)
	binary.BigEndian.PutUint64(buf[ed25519.SignatureSize:], uint64(sp.t.UnixMilli()))
	copy(buf[ed25519.SignatureSize+8:], sp.p)
	return buf
}

// PublicKey returns the public key this record belongs to.
func (sp Record) PublicKey() ed25519.PublicKey {
	return sp.pub
}

// Time returns the timestamp that was used to sign this record.
func (sp Record) Time() time.Time {
	return sp.t
}

// Message returns the underlying DNS record.
func (sp Record) Message() dnsmessage.Message {
	return sp.m
}

// signable returns a bencoded packet that is used for signature verification.
func signable(t time.Time, p []byte) []byte {
	s := fmt.Sprintf("3:seqi%de1:v%d:", t.UnixMilli(), len(p))
	return append([]byte(s), p...)
}
