package hmac

import (
	"bytes"
	"hash"

	"crypto/md5"
)

// MD5 represents a struct containing the necessary stuff to perform HMAC-MD5
type MD5 struct {
	outer hash.Hash
	inner hash.Hash

	opad [md5.BlockSize]byte
	ipad [md5.BlockSize]byte

	buf []byte
}

var (
	ipadBase []byte = bytes.Repeat([]byte{0x36}, md5.BlockSize)
	opadBase []byte = bytes.Repeat([]byte{0x5c}, md5.BlockSize)
)

func New() *MD5 {
	return &MD5{outer: md5.New(), inner: md5.New(), buf: make([]byte, md5.Size)}
}

// CalculateMD5 calculates a HMAC-MD5 checksum of the data and saves it in `out`. `out` should be an array slice of size 16
func (h *MD5) CalculateMD5(key []byte, data []byte, out []byte) {
	copy(h.ipad[:], ipadBase)
	copy(h.opad[:], opadBase)

	if len(key) > md5.BlockSize {
		// If key is too big, hash it.
		h.outer.Write(key)
		key = h.outer.Sum(h.buf[:0])
	}

	for i, k := range key {
		h.ipad[i] ^= k
		h.opad[i] ^= k
	}

	h.inner.Write(h.ipad[:])
	h.inner.Write(data)
	h.inner.Sum(h.buf[:0])

	h.outer.Reset()
	h.outer.Write(h.opad[:])
	h.outer.Write(h.buf)
	h.outer.Sum(out[:0])

	h.outer.Reset()
	h.inner.Reset()
}
