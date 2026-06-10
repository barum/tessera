// Microbenchmarks for the Go TesseraSeal reference.
// Output mirrors tessera-id/go/bench_test.go.
//
//	cd tessera-seal/go && go test -bench=. -benchmem
package tesseraseal

import "testing"

func BenchmarkKeygen(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, _, err := GenerateKeypair(SuiteMLKEM1024AESGCM); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkEncrypt1KB_AESGCM(b *testing.B) {
	_, pub, _ := GenerateKeypair(SuiteMLKEM1024AESGCM)
	pt := make([]byte, 1024)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := Encrypt(pt, pub, SuiteMLKEM1024AESGCM, nil, 0, 0); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDecrypt1KB_AESGCM(b *testing.B) {
	priv, pub, _ := GenerateKeypair(SuiteMLKEM1024AESGCM)
	pt := make([]byte, 1024)
	env, _ := Encrypt(pt, pub, SuiteMLKEM1024AESGCM, nil, 0, 0)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := Decrypt(env, priv, nil); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkEncrypt1MB_AESGCM(b *testing.B) {
	_, pub, _ := GenerateKeypair(SuiteMLKEM1024AESGCM)
	pt := make([]byte, 1024*1024)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := Encrypt(pt, pub, SuiteMLKEM1024AESGCM, nil, 0, 0); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDecrypt1MB_AESGCM(b *testing.B) {
	priv, pub, _ := GenerateKeypair(SuiteMLKEM1024AESGCM)
	pt := make([]byte, 1024*1024)
	env, _ := Encrypt(pt, pub, SuiteMLKEM1024AESGCM, nil, 0, 0)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := Decrypt(env, priv, nil); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkPeekHeader(b *testing.B) {
	_, pub, _ := GenerateKeypair(SuiteMLKEM1024AESGCM)
	env, _ := Encrypt([]byte("x"), pub, SuiteMLKEM1024AESGCM, nil, 0, 0)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = PeekHeader(env)
	}
}

// Hybrid suite 0x06: ML-KEM-1024 + X25519 + AES-256-GCM + UtC.

func BenchmarkKeygenHybrid(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, _, err := GenerateKeypair(SuiteHybridX25519MLKEM1024AESGCM); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkEncrypt1KB_Hybrid(b *testing.B) {
	_, pub, _ := GenerateKeypair(SuiteHybridX25519MLKEM1024AESGCM)
	pt := make([]byte, 1024)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := Encrypt(pt, pub, SuiteHybridX25519MLKEM1024AESGCM, nil, 0, 0); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDecrypt1KB_Hybrid(b *testing.B) {
	priv, pub, _ := GenerateKeypair(SuiteHybridX25519MLKEM1024AESGCM)
	pt := make([]byte, 1024)
	env, _ := Encrypt(pt, pub, SuiteHybridX25519MLKEM1024AESGCM, nil, 0, 0)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := Decrypt(env, priv, nil); err != nil {
			b.Fatal(err)
		}
	}
}
