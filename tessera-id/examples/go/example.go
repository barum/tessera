// TesseraID basics: generate, encode, decode, sort.
//
// Run from the repo root (resolved via go.work):
//
//	go run ./tessera-id/examples/go
package main

import (
	"bytes"
	"fmt"
	"log"

	tesseraid "github.com/barum/tessera/tessera-id/go"
)

func main() {
	// 41-byte Standard (variant 0x01) IDs; sort by generation order.
	var ids [3][tesseraid.SizeBytes]byte
	for i := range ids {
		id, err := tesseraid.New()
		if err != nil {
			log.Fatal(err)
		}
		ids[i] = id
	}
	for i := 1; i < len(ids); i++ {
		if bytes.Compare(ids[i-1][:], ids[i][:]) >= 0 {
			log.Fatal("IDs must sort by generation order (time-ordered)")
		}
	}

	b64 := tesseraid.EncodeBase64URL(ids[0]) // 55 chars, canonical wire text
	b32 := tesseraid.EncodeCrockford(ids[0]) // 66 chars, human-typable Crockford
	if got, err := tesseraid.DecodeBase64URL(b64); err != nil || got != ids[0] {
		log.Fatal("Base64URL round-trip failed")
	}
	if got, err := tesseraid.DecodeCrockford(b32); err != nil || got != ids[0] {
		log.Fatal("Crockford round-trip failed")
	}

	fields, err := tesseraid.Decode(ids[0][:])
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("id=%s\n", b64)
	fmt.Printf("variant=0x%02x ts_ms=%d counter=%d\n", fields.Variant, fields.TimestampMS, fields.Counter)

	// HLC variant (0x02) for distributed causality.
	var gen tesseraid.HLCGenerator
	hlc, err := gen.New(nil)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("hlc=%s\n", tesseraid.EncodeBase64URL(hlc))
}
