package kerberos

import (
	"bytes"
	"crypto/rc4"
	"encoding/hex"
	"testing"
)

const helloWorldNTLMHash = "e1cf2a4200eecdf14a4691bbf1ba255a"

func TestNTLNHash(t *testing.T) {
	hash, _ := NTLMHash("hello world")
	if hex.EncodeToString(hash) != helloWorldNTLMHash {
		t.Error("Expected:", helloWorldNTLMHash, "Actual:", hash)
	}
}

func TestRC4Crypt(t *testing.T) {
	key, data := []byte("hello world"), []byte("goodbyte world")

	enc, _ := rc4.NewCipher(key)
	out := make([]byte, len(data))
	enc.XORKeyStream(out, data)

	out2 := make([]byte, len(data))
	rc4crypt(key, data, out)

	if bytes.Equal(out, out2) {
		t.Error("Expected:", out, "Actual:", out2)
	}
}

func BenchmarkNTLMHash(b *testing.B) {
	for i := 0; i < b.N; i++ {
		NTLMHash("the quick brown fox jumps over the lazy dog")
	}
}

func BenchmarkRC4Crypt(b *testing.B) {
	key, data := []byte("hello world"), []byte("goodbye world")
	out, nullSlice := make([]byte, len(data)), make([]byte, len(data))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		copy(out[:], nullSlice[:])
		enc, _ := rc4.NewCipher(key)
		enc.XORKeyStream(out, data)
	}
}

func BenchmarkMyRC4Crypt(b *testing.B) {
	key, data := []byte("hello world"), []byte("goodbye world")
	out, nullSlice := make([]byte, len(data)), make([]byte, len(data))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		copy(out[:], nullSlice[:])
		rc4crypt(key, data, out)
	}
}

func BenchmarkDecrypt(b *testing.B) {
	key, _ := hex.DecodeString("643f5625a4e347d9208dba1c3f299af4")
	data, _ := hex.DecodeString("18e20753047d9b8e51d43fae031a6445a7250819b12bd1d8ff2b21c79c152e2f2cad68b1c2ddfac358d0ebeabdf0eac723433c31455f3693b130100ee5fb3ad623e6deddbf806efd9590e9d8daee06757c9dca91053177c193bc3e6e8707e9228c4b237d2ca83ad3c7323fa3de285cf43806633e7ae81e0b0e5b39ea57a966e1f270ec8ddbc6d0a520cbd959ca36a76237d9be59af8243b2e9f91ce3cac967e2384719882df8ca3a8ccfeeb66cb501a779a6b8312721afe21a74b4d9ff10bcbc12f585f051728b8cebb4698514e8ad69559627d70c5f20ee8f2bebf15c19f768b612e68b02bb371638bd1d997f67523811f66d1759bd8903c414ef358e281ab5fd958b4e974be3ceda15ac49733f2baaa5ec5c3e42b22675ef5bb2ef274f4dc3d99db1df9d181621a2b21d494233323f0fd4f7af12527ca1664e0377a96f3192139f53cfb02077255793698b7c29588371fcf03adb0d27fb2af6762598eadcd317be853b791e52a9dc5a66626f9c8d25846f5822f994f741b3137f2780f790071c34dcad59919a8f5eece5da9d2ea0faa011744b57fa5c9b2c8ec856b697fd276e2d8907b56f463d03977f81245f5b3acc3116f9a4aba3336568be1b32f115d4cba2d51bbfcc94af70cec3e130541cd8c08561cb8874bfe49efc41770c6e270853be533d7d558adeb1e1ae0ced7401f5fc59f9d8d32b8ba74d2b5ebff860a861ae459f21a0df9821ab9c447480d6e8f948e1be435f4a3d3f94966de49d60f4126336fa6d1fc9ca9de479fc0f5b5abc5705a8734cc6c3d0f796c426eaccd506fc6f1b86305bfc0e31f4eba4d061f45bb0b43a1785844d73de967562f03a1056186efe5677414cacae52247e6dd14e492add476d928a34eda49c680968b3fed5ad5b9742234708376ed6b6c7268aa86f54735e6717e393b15d21e1d4ab737ddfd841baeff4eb0b6872418bc56762e143335f6306aad4615df0a79285279c1fcac547cf5511cd6b373807799d40ac704afd8461f0a6e95d79e9d8bc867cb975e57c550adae0d8c4c0ab52730246641d09ae6ebcad6e18cf16fbb6c7932a1cde74239db1a93d2e9e6604fdebfd252185cc20eb2019b6b1b187748fc17670066ecc87705bf4d9cef3672062233729eb6cd1fb14c6fe29987b21c18f289ac7e638a570d1fa098727edb66cab36f1dc2f3b7a0739d320301eb9db52ce6981bfe9174d5e8379d5cf214cc5b97b9fde96e4ec4a212a91d175649ef3fed7e551d0bf7d968d8fd17aad4c441b0815ed6731aa0cf5dd4181d3d9e284eb7df20c9dcb9b3e8893a3f9133a1ae49fb362f06f307385bddaa03f77351a9bff4db485f1ad22867517400e85009617e2b6f1a85f225e3ad96787dd45ad3203db3423c8198c8a7397e62e83df28aa579b1f254d587c369bd6d0e819d537e312e95f3d6de7fdc6ca10c5e7b542f2")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Decrypt(key, 2, data)
	}
}
