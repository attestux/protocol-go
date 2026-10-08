package frame

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	attestuxv1 "github.com/attestux/protocol-go/attestux/v1"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
)

const (
	prefixSize = 4

	MaxEvidencePayload = 32 << 20
	MaxControlPayload  = 64 << 10
)

// Frame limits leave room for the oneof tag and length around a payload at
// its own limit, so a 32 MiB evidence message still fits its frame.
var (
	MaxEvidenceFrame = envelopeSize(MaxEvidencePayload)
	MaxControlFrame  = envelopeSize(MaxControlPayload)
)

var (
	ErrTooLarge  = errors.New("frame exceeds limit")
	ErrMalformed = errors.New("malformed frame")
)

func envelopeSize(payload int) int {
	return protowire.SizeTag(1) + protowire.SizeBytes(payload)
}

func limitFor(frame *attestuxv1.Frame) int {
	if _, ok := frame.GetPayload().(*attestuxv1.Frame_Evidence); ok {
		return MaxEvidenceFrame
	}
	return MaxControlFrame
}

// Read decodes one frame. limit bounds the allocation before the payload is
// known; each payload is then held to its own limit.
func Read(r io.Reader, limit int) (*attestuxv1.Frame, error) {
	var prefix [prefixSize]byte
	if _, err := io.ReadFull(r, prefix[:]); err != nil {
		return nil, fmt.Errorf("read frame length: %w", err)
	}
	size := binary.BigEndian.Uint32(prefix[:])
	if size > uint32(limit) {
		return nil, fmt.Errorf("%w: %d bytes, limit %d", ErrTooLarge, size, limit)
	}
	body := make([]byte, size)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, fmt.Errorf("read frame: %w", err)
	}
	frame := &attestuxv1.Frame{}
	if err := proto.Unmarshal(body, frame); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	if frame.Payload == nil {
		return nil, fmt.Errorf("%w: no payload", ErrMalformed)
	}
	if own := limitFor(frame); int(size) > own {
		return nil, fmt.Errorf("%w: %d bytes, limit %d", ErrTooLarge, size, own)
	}
	return frame, nil
}

// Write sends the length in its own transfer: the phone reads it with an
// exact-size USB request before it knows the body size.
func Write(w io.Writer, frame *attestuxv1.Frame) error {
	if frame.GetPayload() == nil {
		return errors.New("frame has no payload")
	}
	body, err := proto.Marshal(frame)
	if err != nil {
		return err
	}
	if limit := limitFor(frame); len(body) > limit {
		return fmt.Errorf("%w: %d bytes, limit %d", ErrTooLarge, len(body), limit)
	}
	var prefix [prefixSize]byte
	binary.BigEndian.PutUint32(prefix[:], uint32(len(body)))
	if _, err := w.Write(prefix[:]); err != nil {
		return fmt.Errorf("write frame length: %w", err)
	}
	if _, err := w.Write(body); err != nil {
		return fmt.Errorf("write frame: %w", err)
	}
	return nil
}
