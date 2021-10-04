package hmac

import (
	"hash"

	"crypto/md5"
)

type HmacMD5 struct {
	outer hash.Hash
	inner hash.Hash

	opad [md5.BlockSize]byte
	ipad [md5.BlockSize]byte
}

var (
	ipadBase [md5.BlockSize]byte
	opadBase [md5.BlockSize]byte
)

func init() {
	for i := range ipadBase {
		ipadBase[i] = 0x36
	}
	for i := range opadBase {
		opadBase[i] = 0x5c
	}
}

func New() *HmacMD5 {
	return &HmacMD5{outer: md5.New(), inner: md5.New()}
}

// CalculateHMACMD5 calculates a HMAC-MD5 checksum of the data
func (h *HmacMD5) CalculateHMACMD5(key []byte, data []byte) []byte {
	defer func() {
		h.outer.Reset()
		h.inner.Reset()
	}()

	copy(h.ipad[:], ipadBase[:])
	copy(h.opad[:], opadBase[:])

	if len(key) > md5.BlockSize {
		// If key is too big, hash it.
		h.outer.Write(key)
		key = h.outer.Sum(nil)
	}

	for i := range key {
		h.ipad[i] ^= key[i]
		h.opad[i] ^= key[i]
	}

	h.inner.Write(h.ipad[:])
	h.inner.Write(data)
	in := h.inner.Sum(nil)

	h.outer.Reset()
	h.outer.Write(h.opad[:])
	h.outer.Write(in)
	return h.outer.Sum(nil)
}
