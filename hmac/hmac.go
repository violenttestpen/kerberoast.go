package hmac

import (
	"hash"
	"sync"

	"crypto/md5"
)

type hmacMD5Struct struct {
	outer hash.Hash
	inner hash.Hash
}

var emptyHmacPad = make([]byte, md5.BlockSize*2)

var hmacBufPool = sync.Pool{New: func() interface{} { buf := make([]byte, md5.BlockSize*2); return &buf }}
var md5Pool = sync.Pool{New: func() interface{} { return &hmacMD5Struct{outer: md5.New(), inner: md5.New()} }}

// CalculateHMACMD5 calculates a HMAC-MD5 checksum of the data
func CalculateHMACMD5(key []byte, data []byte) []byte {
	hmacMD5Obj := md5Pool.Get().(*hmacMD5Struct)
	outer, inner := hmacMD5Obj.outer, hmacMD5Obj.inner
	defer func() {
		outer.Reset()
		inner.Reset()
		md5Pool.Put(hmacMD5Obj)
	}()

	pad := hmacBufPool.Get().(*[]byte)
	ipad, opad := (*pad)[:md5.BlockSize], (*pad)[md5.BlockSize:]
	defer func() {
		copy(*pad, emptyHmacPad)
		hmacBufPool.Put(pad)
	}()

	if len(key) > md5.BlockSize {
		// If key is too big, hash it.
		outer.Write(key)
		key = outer.Sum(nil)
	}

	copy(ipad, key)
	copy(opad, key)

	for i := range ipad[:] {
		ipad[i] ^= 0x36
	}
	for i := range opad[:] {
		opad[i] ^= 0x5c
	}

	inner.Write(ipad)
	inner.Write(data)
	in := inner.Sum(nil)

	outer.Reset()
	outer.Write(opad)
	outer.Write(in)
	return outer.Sum(nil)
}
