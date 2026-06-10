// Interop, decode side: consume one TesseraID emitted by the Python encoder
// (../../python/interop_encode.py prints a Base64URL line then a Crockford
// line) and assert both text forms carry the same 41 bytes — wire output
// generated in one language MUST decode byte-identically in every other.
//
// Run from the repo root:
//
//	PYTHONPATH=tessera-id/python python3 tessera-id/examples/python/interop_encode.py \
//	    | go run ./tessera-id/examples/go/interop
package main

import (
	"bufio"
	"fmt"
	"log"
	"os"

	tesseraid "github.com/barum/tessera/tessera-id/go"
)

func main() {
	sc := bufio.NewScanner(os.Stdin)
	readLine := func() string {
		if !sc.Scan() {
			log.Fatal("expected two input lines: Base64URL then Crockford")
		}
		return sc.Text()
	}
	b64Line, b32Line := readLine(), readLine()

	fromB64, err := tesseraid.DecodeBase64URL(b64Line)
	if err != nil {
		log.Fatalf("Base64URL decode: %v", err)
	}
	fromB32, err := tesseraid.DecodeCrockford(b32Line)
	if err != nil {
		log.Fatalf("Crockford decode: %v", err)
	}
	if fromB64 != fromB32 {
		log.Fatal("Base64URL and Crockford forms decoded to different bytes")
	}
	fields, err := tesseraid.Decode(fromB64[:])
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("interop OK: variant=0x%02x ts_ms=%d counter=%d\n",
		fields.Variant, fields.TimestampMS, fields.Counter)
}
