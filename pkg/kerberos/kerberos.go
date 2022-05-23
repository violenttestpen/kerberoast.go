package kerberos

import (
	"bytes"
	"crypto/md5"
	"errors"
	"hash"
	"os"

	"github.com/jcmturner/gokrb5/messages"
	"github.com/violenttestpen/kerberoast.go/pkg/hmac"

	"golang.org/x/crypto/md4"
)

// ErrChecksum represents an error during decryption
var ErrChecksum = errors.New("Checksum Error")

// ErrNoTicketsFound represents an error when presented with an invalid Kerberos ticket
var ErrNoTicketsFound = errors.New("No tickets found")

var rc4Box [256]uint8

// TGSRepStruct contains the components used for TGS-REP roasting
type TGSRepStruct struct {
	md4Hasher hash.Hash
	hmacMD5   *hmac.MD5
	rc4Buf    []byte
	utf16Buf  []byte

	K1       [md5.Size]byte
	K3       [md5.Size]byte
	checksum [md5.Size]byte
}

func init() {
	for i := range rc4Box {
		rc4Box[i] = uint8(i)
	}
}

// New returns a newly allocated instance of TGSRepStruct
func New() *TGSRepStruct {
	return &TGSRepStruct{md4Hasher: md4.New(), hmacMD5: hmac.New()}
}

// ExtractTicketFromKirbi extracts the Kerberos ticket from file
func ExtractTicketFromKirbi(filename string) ([]byte, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	return extractTicket(data)
}

func extractTicket(data []byte) ([]byte, error) {
	if data[0] == 0x76 {
		var krbCred messages.KRBCred
		if err := krbCred.Unmarshal(data); err != nil {
			return nil, err
		}
		return krbCred.Tickets[0].EncPart.Cipher, nil
	}
	return nil, ErrNoTicketsFound
}

// NTLMHash performs a NTLM hash algorithm on the input and saves it in `out`. `out` should be an array slice of size 16
func (k *TGSRepStruct) NTLMHash(s string, out []byte) error {
	k.utf16Buf = utf16Encode(s, k.utf16Buf)
	if _, err := k.md4Hasher.Write(k.utf16Buf); err != nil {
		return err
	}

	k.md4Hasher.Sum(out[:0])
	k.md4Hasher.Reset()
	return nil
}

func utf16Encode(s string, b []byte) []byte {
	codes := []rune(s) // codes := utf16.Encode([]rune(s))
	b = b[:0]
	for _, r := range codes {
		b = append(b, byte(r))
		b = append(b, byte(r>>8))
	}
	return b
}

// Decrypt tries to decrypt the ticket data with the supplied key
func (k *TGSRepStruct) Decrypt(key []byte, msgType []byte, edata []byte) (data []byte, nonce []byte, err error) {
	_ = edata[16] // eliminate bounds check

	// Calculate K1, K2
	k.hmacMD5.CalculateMD5(key, msgType, k.K1[:])

	// Calculate K3
	k.hmacMD5.CalculateMD5(k.K1[:], edata[:16], k.K3[:])

	// Perform RC4 encryption
	k.rc4Buf = append(k.rc4Buf, edata[16:]...)
	rc4crypt(k.K3[:], k.rc4Buf, edata[16:])

	// Calculate checksum
	k.hmacMD5.CalculateMD5(k.K1[:], k.rc4Buf, k.checksum[:])

	if bytes.Equal(k.checksum[:], edata[:16]) {
		data, nonce = k.rc4Buf[8:], k.rc4Buf[:8]
	} else {
		err = ErrChecksum
	}
	k.rc4Buf = k.rc4Buf[:0]

	return
}

func rc4crypt(key, dst, src []byte) {
	var box [256]uint8
	var x, y, xValue, yValue uint8

	// Sanity check and bounds check elimination
	if len(dst) < len(src) {
		return
	}

	copy(box[:], rc4Box[:])

	for i, index, length := 0, 0, len(key); i < 256; i++ {
		iValue := box[i]
		x += iValue + key[index] // x = (x + box[i] + key[i%len(key)]) % 256
		box[i], box[x] = box[x], iValue

		index++
		if index == length {
			index = 0
		}
	}

	x, y = 0, 0
	for i := range src {
		x++                                  // x = (x + 1) % 256
		xValue = box[x]                      //
		y += xValue                          // y = (y + box[x]) % 256
		yValue = box[y]                      //
		box[x], box[y] = yValue, xValue      //
		dst[i] = src[i] ^ box[xValue+yValue] // char ^ byte(box[(box[x]+box[y])%256])
	}
}
