package kerberos

import (
	"bytes"
	"crypto/rc4"
	"encoding/hex"
	"testing"
)

const keyString = "f2cddb01eb3bd8499f409dc938b6e2b7"
const dataString = "af6661cfa32b04770f32d452280e7da030e997a75550ff68c0acfa6ad03021423224f16fd4acbb47ea8bb124d9a0fc120f5dc6ade8a79dce3e00626e16631fcf116c20e7341e9e563186399c4951a7702f2e2a68141700f2d55a783044a13a2e45842c68678f7621eb89ecf2982dab77e3802399e57aa453f4efd3a8103e4c2ac9b6a6ec6887fa30a355ee0524613fcc61a4bc0de7dac5a36c25c252955cca4d79350d3e7c6f4042ff999c352f32ec739ee6eb65c10e667d283343c5e40d90c15ba6e861abcc7069f14232007a2ddd8a88d7713b1cff7daa7378247ced1f2c8a26dc85409bf4faff4f791c5259cc75479ee74e22d7e52782001941a8b2fd70d791ec37ea2244a99e7cffd12b579e8ea76809e1324c548e2e0492fcfa32248b5b3097c1ec5226dd9014c9cf041b3a20b18d14d863ab9f7d7dfe8a70356a43395d277861afb66971a46d86ae51de7c2f23436f16f3fd56a22111715717cada56047f51c0326e1dd0d9cb32a0df0d3481d1d234f2b9781243e81d36ad3d52eb0b1ba92f07996085624ca438b073bdbaece9f7edf029c2a5e3b2725c7aa1a1ef2a7aacf8d7012c6a543b00f08976c0ef3911721b12211ce895c3130ee0057768b370ac85a4504869a31d1585cd42773dfd4e4d35c7cb3e4d70cb245130307f3057c38daf6a501752ba50fabb82ccb1b52015b3f87b795bbd9548f67cf520193ddc0ebcbbca375041bc02644b18f788ce876e3d6140902db96a5f5ae6fbc7a01becc9039c2907a60bf9287d7b85dd38d4ff94068a04e081f11baa730faabbe5fcc85ba6d7427cf4295179e789922631102ab40024d0b68c6390ba828f07d6186eb0c583a93da07f2e69d28c743df7288e097f931843e70957d603d001272a42ab224c66040173018bfebfedc6d772524fa41ffafdbd2082bdf07188a0026d3e53e051c08b9c0eb21ccecbd3a5404eb82ae4656d2417da66e26cf416ca3b74e4134f07ecb0a1a509e0b2ac894eed6c2b05a00089de70b7db556160355b07c9bad845b82659f6c57932c1e2d97d2522f957bb9445253d5a252c1a8ca78700a2d676fb1aafa7938b03ba270030d4b80af6e413b12e7a975efbc7165a3635e3b543f00280c9434a46ddde306f6676e726a21a645dc070d9cfdaadbe6f0985fb61f3c49430350203b91a61ad44820bff4993f7d5cdc50fcc20904cbd00b3dd4ea49ae41cd85bcb9fe852fce6265b66cd52005b7389ef9954279725f992cc70aa8e3fdd30008f2b064e533f578e1c3d428c2c2fd5b641b6b3d11c05e3a768180347a3645941fdd5f064bbb2bb59e514ff3605d7bc268cc7e8fcf0fb0757c41cc5b64824c54ef917de42e62bdddb973e13f0b1b9bf3f5dbc3df9f88ab0168572d505bb0e179dbff3c53b4fb043b912b8a65a047f58c0c60bdf4f583ab96d"

const helloWorldString = "hello world"
const helloWorldNTLMHash = "e1cf2a4200eecdf14a4691bbf1ba255a"

func TestNTLNHash(t *testing.T) {
	hash, _ := NTLMHash(helloWorldString)
	if hex.EncodeToString(hash) != helloWorldNTLMHash {
		t.Error("Expected:", helloWorldNTLMHash, "Actual:", hash)
	}
}

func TestRC4Crypt(t *testing.T) {
	key, _ := hex.DecodeString(keyString)
	data, _ := hex.DecodeString(dataString)

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
		NTLMHash(dataString)
	}
}

func BenchmarkRC4Crypt(b *testing.B) {
	key, _ := hex.DecodeString(keyString)
	data, _ := hex.DecodeString(dataString)
	out, nullSlice := make([]byte, len(data)), make([]byte, len(data))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		copy(out[:], nullSlice[:])
		enc, _ := rc4.NewCipher(key)
		enc.XORKeyStream(out, data)
	}
}

func BenchmarkMyRC4Crypt(b *testing.B) {
	key, _ := hex.DecodeString(keyString)
	data, _ := hex.DecodeString(dataString)
	out, nullSlice := make([]byte, len(data)), make([]byte, len(data))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		copy(out[:], nullSlice[:])
		rc4crypt(key, data, out)
	}
}

func BenchmarkDecrypt(b *testing.B) {
	key, _ := hex.DecodeString(keyString)
	data, _ := hex.DecodeString(dataString)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Decrypt(key, 2, data)
	}
}
