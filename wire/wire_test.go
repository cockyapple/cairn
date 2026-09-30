package wire

import (
	"bytes"
	"errors"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	var w Writer
	w.U8(7)
	w.U32(0xdeadbeef)
	w.U64(1 << 40)
	w.Fixed([]byte{1, 2, 3})
	w.String("héllo")
	w.Bytes(nil)

	r := NewReader(w.Out())
	if r.U8() != 7 || r.U32() != 0xdeadbeef || r.U64() != 1<<40 {
		t.Fatal("integer mismatch")
	}
	if !bytes.Equal(r.Fixed(3), []byte{1, 2, 3}) {
		t.Fatal("fixed mismatch")
	}
	if r.String() != "héllo" {
		t.Fatal("string mismatch")
	}
	if len(r.Bytes()) != 0 {
		t.Fatal("empty bytes mismatch")
	}
	if err := r.Done(); err != nil {
		t.Fatal(err)
	}
}

func TestBigEndianLayout(t *testing.T) {
	var w Writer
	w.U32(1)
	w.U64(2)
	want := []byte{0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 2}
	if !bytes.Equal(w.Out(), want) {
		t.Fatalf("got %x want %x", w.Out(), want)
	}
}

func TestShortAndTrailing(t *testing.T) {
	r := NewReader([]byte{1, 2})
	r.U32()
	if !errors.Is(r.Err(), ErrShort) {
		t.Fatalf("want ErrShort, got %v", r.Err())
	}
	if !errors.Is(NewReaderDone([]byte{1}), ErrTrailing) {
		t.Fatal("want ErrTrailing")
	}
}

func NewReaderDone(b []byte) error { return NewReader(b).Done() }

func TestHostileLengthDoesNotAllocate(t *testing.T) {
	// claims a 4 GiB-1 body but supplies nothing
	r := NewReader([]byte{0xff, 0xff, 0xff, 0xff})
	if r.Bytes() != nil || !errors.Is(r.Err(), ErrTooLarge) {
		t.Fatalf("want ErrTooLarge, got %v", r.Err())
	}
	r = NewReader([]byte{0, 0, 0, 9, 1})
	r.Bytes()
	if !errors.Is(r.Err(), ErrShort) {
		t.Fatalf("want ErrShort, got %v", r.Err())
	}
	r = NewReader([]byte{0xff, 0xff, 0xff, 0xff})
	if r.Count(16) != 0 || !errors.Is(r.Err(), ErrTooLarge) {
		t.Fatal("count limit not enforced")
	}
}

func TestInvalidUTF8(t *testing.T) {
	r := NewReader([]byte{0, 0, 0, 1, 0xff})
	_ = r.String()
	if !errors.Is(r.Err(), ErrUTF8) {
		t.Fatalf("want ErrUTF8, got %v", r.Err())
	}
}

func TestErrorIsSticky(t *testing.T) {
	r := NewReader(nil)
	r.U8()
	r.U64()
	if !errors.Is(r.Err(), ErrShort) {
		t.Fatal("first error must persist")
	}
}
