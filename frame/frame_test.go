package frame

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/attestux/protocol-go/attestux/v1"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
)

func challengeFrame(version uint32) *attestuxv1.Frame {
	return &attestuxv1.Frame{Payload: &attestuxv1.Frame_Challenge{
		Challenge: &attestuxv1.AttestationChallenge{ProtocolVersion: version},
	}}
}

func evidenceFrame(payload []byte) *attestuxv1.Frame {
	return &attestuxv1.Frame{Payload: &attestuxv1.Frame_Evidence{Evidence: payload}}
}

func errorFrame(message string) *attestuxv1.Frame {
	return &attestuxv1.Frame{Payload: &attestuxv1.Frame_Error{
		Error: &attestuxv1.ProtocolError{Message: message},
	}}
}

func TestWireLayoutIsALengthBeforeAFrameMessage(t *testing.T) {
	var buf bytes.Buffer
	if err := Write(&buf, challengeFrame(1)); err != nil {
		t.Fatal(err)
	}
	want := []byte{0, 0, 0, 4, 0x0a, 2, 0x08, 1}
	if !bytes.Equal(buf.Bytes(), want) {
		t.Fatalf("encoded frame %x, want %x", buf.Bytes(), want)
	}
	got, err := Read(bytes.NewReader(want), MaxControlFrame)
	if err != nil || !proto.Equal(got, challengeFrame(1)) {
		t.Fatalf("Read = %v, %v; want the challenge", got, err)
	}
}

func TestWriteSendsLengthAndFrameSeparately(t *testing.T) {
	var writes []int
	w := writerFunc(func(p []byte) (int, error) {
		writes = append(writes, len(p))
		return len(p), nil
	})
	if err := Write(w, challengeFrame(1)); err != nil {
		t.Fatal(err)
	}
	if len(writes) != 2 || writes[0] != prefixSize || writes[1] != 4 {
		t.Fatalf("write sizes = %v, want the length then the frame", writes)
	}
}

func TestWriteRejectsFramesWithoutPayload(t *testing.T) {
	for name, frame := range map[string]*attestuxv1.Frame{"nil": nil, "empty": {}} {
		var buf bytes.Buffer
		if err := Write(&buf, frame); err == nil {
			t.Errorf("Write accepted a %s frame", name)
		}
		if buf.Len() != 0 {
			t.Errorf("Write emitted %d bytes for a %s frame", buf.Len(), name)
		}
	}
}

func TestWriteRejectsOversizedFramesBeforeMarshaling(t *testing.T) {
	message := errorFrame(strings.Repeat("\xff", MaxControlFrame))
	if _, err := proto.Marshal(message); err == nil {
		t.Fatal("fixture must fail marshaling because its message is not valid UTF-8")
	}
	var wire bytes.Buffer
	if err := Write(&wire, message); !errors.Is(err, ErrTooLarge) || wire.Len() != 0 {
		t.Fatalf("Write = %v, wrote %d bytes; want size rejection before marshaling", err, wire.Len())
	}
}

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }

func TestWriteReportsFrameFailure(t *testing.T) {
	broken := errors.New("endpoint stalled")
	written := 0
	w := writerFunc(func(p []byte) (int, error) {
		if written == prefixSize {
			return 0, broken
		}
		written += len(p)
		return len(p), nil
	})
	err := Write(w, errorFrame("x"))
	if !errors.Is(err, broken) || !strings.Contains(err.Error(), "write frame:") {
		t.Fatalf("Write error = %v, want the frame write failure", err)
	}
}

// Shrinks the frame's bytes field until the frame encodes to exactly size.
func framedTo(t *testing.T, size int, build func(n int) *attestuxv1.Frame) *attestuxv1.Frame {
	t.Helper()
	for n := size; n >= 0; n-- {
		if frame := build(n); proto.Size(frame) <= size {
			if proto.Size(frame) != size {
				t.Fatalf("no payload size encodes to %d bytes", size)
			}
			return frame
		}
	}
	t.Fatalf("no payload size encodes to %d bytes", size)
	return nil
}

func lengthPrefix(size int) []byte {
	return binary.BigEndian.AppendUint32(nil, uint32(size))
}

func TestPayloadLimitDependsOnPayload(t *testing.T) {
	evidencePayload := make([]byte, MaxEvidenceFrame+1)
	evidence := func(n int) *attestuxv1.Frame { return evidenceFrame(evidencePayload[:n]) }
	control := func(n int) *attestuxv1.Frame { return errorFrame(strings.Repeat("e", n)) }
	for _, test := range []struct {
		name  string
		limit int
		build func(n int) *attestuxv1.Frame
	}{
		{"evidence", MaxEvidenceFrame, evidence},
		{"control", MaxControlFrame, control},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := Write(io.Discard, framedTo(t, test.limit, test.build)); err != nil {
				t.Fatalf("a frame at the limit was rejected: %v", err)
			}
			err := Write(io.Discard, framedTo(t, test.limit+1, test.build))
			if !errors.Is(err, ErrTooLarge) {
				t.Fatalf("Write error = %v, want ErrTooLarge", err)
			}
			// At the limit, decoding gets as far as the missing frame.
			_, err = Read(bytes.NewReader(lengthPrefix(test.limit)), test.limit)
			if !errors.Is(err, io.EOF) || errors.Is(err, ErrTooLarge) {
				t.Fatalf("Read error = %v, want a short frame read", err)
			}
			_, err = Read(bytes.NewReader(lengthPrefix(test.limit+1)), test.limit)
			if !errors.Is(err, ErrTooLarge) {
				t.Fatalf("Read error = %v, want ErrTooLarge", err)
			}
		})
	}
}

func TestReadHoldsControlPayloadsToTheirOwnLimit(t *testing.T) {
	for _, test := range []struct {
		name    string
		message *attestuxv1.Frame
	}{
		{"error", framedTo(t, MaxControlFrame+1, func(n int) *attestuxv1.Frame {
			return errorFrame(strings.Repeat("e", n))
		})},
		{"hello", &attestuxv1.Frame{Payload: &attestuxv1.Frame_Hello{Hello: make([]byte, MaxControlPayload+1)}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			body, err := proto.Marshal(test.message)
			if err != nil {
				t.Fatal(err)
			}
			_, err = Read(bytes.NewReader(append(lengthPrefix(len(body)), body...)), MaxEvidenceFrame)
			if !errors.Is(err, ErrTooLarge) {
				t.Fatalf("Read error = %v, want ErrTooLarge", err)
			}
		})
	}
}

func TestReadRejectsFramesWithoutPayload(t *testing.T) {
	for name, body := range map[string][]byte{
		"empty":              {},
		"unknown field only": {0x3a, 0x00},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Read(bytes.NewReader(append(lengthPrefix(len(body)), body...)), MaxControlFrame)
			if !errors.Is(err, ErrMalformed) {
				t.Fatalf("Read error = %v, want ErrMalformed", err)
			}
		})
	}
}

// Pinned on both sides: the phone's table has the same two bodies.
func TestReadUsesProtobufFieldSemantics(t *testing.T) {
	for _, test := range []struct {
		name        string
		body        []byte
		want        *attestuxv1.Frame
		wantUnknown []byte
	}{
		{"unknown field kept", []byte{0x0a, 0, 0x42, 0}, challengeFrame(0), []byte{0x42, 0}},
		{"last oneof case wins", []byte{0x12, 0, 0x32, 0}, errorFrame(""), nil},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := Read(bytes.NewReader(append(lengthPrefix(len(test.body)), test.body...)), MaxControlFrame)
			if err != nil {
				t.Fatal(err)
			}
			if unknown := got.ProtoReflect().GetUnknown(); !bytes.Equal(unknown, test.wantUnknown) {
				t.Fatalf("Read unknown fields = %x, want %x", unknown, test.wantUnknown)
			}
			got.ProtoReflect().SetUnknown(nil)
			if !proto.Equal(got, test.want) {
				t.Fatalf("Read = %v, want %v", got, test.want)
			}
		})
	}
}

func FuzzRead(f *testing.F) {
	f.Add([]byte{0, 0, 0, 4, 0x0a, 2, 0x08, 1})
	f.Add([]byte("BAD!\x00\x01\x00\x01\x00\x00\x00\x00"))
	// A short negative enum expands when protobuf re-encodes it.
	payload := []byte{8, 0xff, 0xff, 0xff, 0xff, 0x0f}
	payload = protowire.AppendString(append(payload, 0x12), strings.Repeat("e", MaxControlFrame-14))
	body := protowire.AppendBytes([]byte{0x32}, payload)
	f.Add(append(lengthPrefix(len(body)), body...))
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 1<<20 {
			t.Skip()
		}
		frame, err := Read(bytes.NewReader(raw), MaxEvidenceFrame)
		if err != nil {
			return
		}
		var encoded bytes.Buffer
		if err := Write(&encoded, frame); errors.Is(err, ErrTooLarge) {
			return
		} else if err != nil {
			t.Fatalf("accepted frame cannot be written: %v", err)
		}
		again, err := Read(&encoded, MaxEvidenceFrame)
		if err != nil || !proto.Equal(again, frame) {
			t.Fatalf("re-encoded frame reads back as %v, %v; want %v", again, err, frame)
		}
	})
}

func TestDiscoveryAndEvidenceHaveDifferentLimits(t *testing.T) {
	for _, test := range []struct {
		name    string
		message *attestuxv1.Frame
		limit   int
	}{
		{"hello", &attestuxv1.Frame{Payload: &attestuxv1.Frame_Hello{Hello: make([]byte, MaxControlPayload)}}, MaxControlFrame},
		{"evidence", &attestuxv1.Frame{Payload: &attestuxv1.Frame_Evidence{Evidence: make([]byte, MaxEvidencePayload)}}, MaxEvidenceFrame},
	} {
		t.Run(test.name, func(t *testing.T) {
			var wire bytes.Buffer
			if err := Write(&wire, test.message); err != nil {
				t.Fatal(err)
			}
			decoded, err := Read(&wire, test.limit)
			if err != nil || !proto.Equal(decoded, test.message) {
				t.Fatalf("frame round trip: %v", err)
			}
		})
	}
	oversized := &attestuxv1.Frame{Payload: &attestuxv1.Frame_Hello{Hello: make([]byte, MaxControlPayload+1)}}
	var wire bytes.Buffer
	if err := Write(&wire, oversized); !errors.Is(err, ErrTooLarge) || wire.Len() != 0 {
		t.Fatalf("oversized key discovery write: %v", err)
	}
}

func TestHelloAndResultPayloads(t *testing.T) {
	for _, test := range []struct {
		name  string
		body  []byte
		check func(*attestuxv1.Frame) bool
	}{
		{"hello", []byte{0x22, 5, 0x0a, 3, 0x0a, 1, 0x55}, func(frame *attestuxv1.Frame) bool {
			var hello attestuxv1.AttestationHello
			return proto.Unmarshal(frame.GetHello(), &hello) == nil && bytes.Equal(hello.GetKeys().GetAttestationPublic(), []byte{0x55})
		}},
		{"result", []byte{0x2a, 5, 0x0a, 3, 0x0a, 1, 0x55}, func(frame *attestuxv1.Frame) bool {
			return frame.GetResult().GetReceipt().GetDeviceId() == "U"
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			wire := append(lengthPrefix(len(test.body)), test.body...)
			decoded, err := Read(bytes.NewReader(wire), MaxControlFrame)
			if err != nil || !test.check(decoded) {
				t.Fatalf("payload did not decode: %v, %v", decoded, err)
			}
			var encoded bytes.Buffer
			if err := Write(&encoded, decoded); err != nil || !bytes.Equal(encoded.Bytes(), wire) {
				t.Fatalf("payload did not round trip: %x, %v", encoded.Bytes(), err)
			}
		})
	}
}
