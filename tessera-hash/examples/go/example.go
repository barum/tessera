// TesseraHash basics: hash content, verify, decode.
//
// Run from the repo root (resolved via go.work):
//
//	go run ./tessera-hash/examples/go
package main

import (
	"fmt"
	"log"

	tesserahash "github.com/barum/tessera/tessera-hash/go"
)

func main() {
	content := []byte("the bytes I want a stable content identifier for")

	var gen tesserahash.Generator
	h := gen.New(content) // 73-byte TesseraHash (variant 0x03)
	if !tesserahash.Verify(h[:], content) {
		log.Fatal("verify must pass for the original content")
	}
	if tesserahash.Verify(h[:], []byte("tampered content")) {
		log.Fatal("verify must fail for tampered content")
	}

	b64 := tesserahash.EncodeBase64URL(h) // 98 chars, canonical wire text
	b32 := tesserahash.EncodeCrockford(h) // 117 chars, human-typable Crockford
	if got, err := tesserahash.DecodeBase64URL(b64); err != nil || got != h {
		log.Fatal("Base64URL round-trip failed")
	}
	if got, err := tesserahash.DecodeCrockford(b32); err != nil || got != h {
		log.Fatal("Crockford round-trip failed")
	}

	fields, err := tesserahash.Decode(h[:])
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("hash=%s\n", b64)
	fmt.Printf("variant=0x%02x ts_ms=%d counter=%d\n", fields.Variant, fields.TimestampMS, fields.Counter)
}
