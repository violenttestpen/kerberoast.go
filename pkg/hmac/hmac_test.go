package hmac

import "testing"

var data = []byte("thequickbrownfoxjumpsoverthelazydog")

func BenchmarkHMACMD5(b *testing.B) {
	hmacMD5 := New()
	out := make([]byte, len(data))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		hmacMD5.CalculateMD5([]byte("helloworld"), data, out)
	}
}
