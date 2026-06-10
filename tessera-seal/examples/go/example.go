// TesseraSeal basics: keygen, encrypt, decrypt with TesseraID-as-AD.
//
// Run from the repo root (resolved via go.work):
//
//	go run ./tessera-seal/examples/go
package main

import (
	"bytes"
	"errors"
	"fmt"
	"log"

	tesseraid "github.com/barum/tessera/tessera-id/go"
	tesseraseal "github.com/barum/tessera/tessera-seal/go"
)

func main() {
	// Suite 0x01 (ML-KEM-1024 + AES-256-GCM).
	priv, pub, err := tesseraseal.GenerateKeypair(tesseraseal.SuiteMLKEM1024AESGCM)
	if err != nil {
		log.Fatal(err)
	}

	// 41-byte TesseraID bound as AD (the canonical routing pattern).
	var gen tesseraid.HLCGenerator
	recordID, err := gen.New(nil)
	if err != nil {
		log.Fatal(err)
	}

	plaintext := []byte("the plaintext")
	envelope, err := tesseraseal.Encrypt(plaintext, pub, tesseraseal.SuiteMLKEM1024AESGCM,
		recordID[:], 0 /* ts: wall clock */, 0 /* counter */)
	if err != nil {
		log.Fatal(err)
	}
	got, err := tesseraseal.Decrypt(envelope, priv, recordID[:])
	if err != nil {
		log.Fatal(err)
	}
	if !bytes.Equal(got, plaintext) {
		log.Fatal("round-trip plaintext mismatch")
	}

	hdr, err := tesseraseal.PeekHeader(envelope) // structural only — NOT authenticated
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("suite=0x%02x kem_ct_len=%d ad_len=%d\n", hdr.Suite, hdr.KEMCTLen, hdr.ADLen)

	// Rebinding the envelope to a different TesseraID fails closed.
	otherID, err := gen.New(nil)
	if err != nil {
		log.Fatal(err)
	}
	if _, err := tesseraseal.Decrypt(envelope, priv, otherID[:]); !errors.Is(err, tesseraseal.ErrDecrypt) {
		log.Fatalf("AD mismatch must fail closed with ErrDecrypt, got %v", err)
	}
	fmt.Println("AD mismatch rejected (fail closed)")
}
