// Package wire implements Cairn's canonical binary encoding: big-endian
// fixed-width integers, raw fixed-size arrays, and u32 length-prefixed bytes.
// There is exactly one valid encoding for any value, so hashes and signatures
// are reproducible by an independent implementation.
package wire

import (
	"encoding/binary"
	"errors"
	"unicode/utf8"
)

var (
	ErrShort    = errors.New("wire: input too short")
	ErrTrailing = errors.New("wire: trailing bytes")
	ErrTooLarge = errors.New("wire: length exceeds limit")
	ErrUTF8     = errors.New("wire: string is not valid UTF-8")
)

// MaxBytes bounds any single length-prefixed field (16 MiB).
const MaxBytes = 1 << 24

type Writer struct{ buf []byte }

func (w *Writer) U8(v uint8) { w.buf = append(w.buf, v) }

func (w *Writer) U32(v uint32) { w.buf = binary.BigEndian.AppendUint32(w.buf, v) }

func (w *Writer) U64(v uint64) { w.buf = binary.BigEndian.AppendUint64(w.buf, v) }

// Fixed appends b verbatim; the reader must know the length.
func (w *Writer) Fixed(b []byte) { w.buf = append(w.buf, b...) }

func (w *Writer) Bytes(b []byte) {
	w.U32(uint32(len(b)))
	w.buf = append(w.buf, b...)
}

func (w *Writer) String(s string) { w.Bytes([]byte(s)) }

// Out returns the encoded bytes.
func (w *Writer) Out() []byte { return w.buf }

type Reader struct {
	b   []byte
	err error
}

func NewReader(b []byte) *Reader { return &Reader{b: b} }

func (r *Reader) take(n int) []byte {
	if r.err != nil {
		return nil
	}
	if n < 0 || len(r.b) < n {
		r.err = ErrShort
		return nil
	}
	out := r.b[:n]
	r.b = r.b[n:]
	return out
}

func (r *Reader) U8() uint8 {
	b := r.take(1)
	if b == nil {
		return 0
	}
	return b[0]
}

func (r *Reader) U32() uint32 {
	b := r.take(4)
	if b == nil {
		return 0
	}
	return binary.BigEndian.Uint32(b)
}

func (r *Reader) U64() uint64 {
	b := r.take(8)
	if b == nil {
		return 0
	}
	return binary.BigEndian.Uint64(b)
}

// Fixed returns a copy of the next n bytes.
func (r *Reader) Fixed(n int) []byte {
	b := r.take(n)
	if b == nil {
		return nil
	}
	return append([]byte(nil), b...)
}

func (r *Reader) Bytes() []byte {
	n := r.U32()
	if r.err != nil {
		return nil
	}
	if n > MaxBytes {
		r.err = ErrTooLarge
		return nil
	}
	return r.Fixed(int(n))
}

func (r *Reader) String() string {
	b := r.Bytes()
	if r.err != nil {
		return ""
	}
	if !utf8.Valid(b) {
		r.err = ErrUTF8
		return ""
	}
	return string(b)
}

// Count reads a u32 element count and rejects anything above max, so a hostile
// count cannot force a huge allocation.
func (r *Reader) Count(max uint32) int {
	n := r.U32()
	if r.err != nil {
		return 0
	}
	if n > max {
		r.err = ErrTooLarge
		return 0
	}
	return int(n)
}

func (r *Reader) Err() error { return r.err }

// Done returns the first error, or ErrTrailing if input remains.
func (r *Reader) Done() error {
	if r.err != nil {
		return r.err
	}
	if len(r.b) != 0 {
		return ErrTrailing
	}
	return nil
}
