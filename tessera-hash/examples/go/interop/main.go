// Interop, decode side: consume the Crockford TesseraHash emitted by the
// Python encoder (../../python/interop_encode.py hashes a fixed content at a
// fixed (ts, counter)), verify the SHAKE-256 tail against the same content,
// recompute the hash at the same (ts, counter), and assert byte-identity.
//
// Run from the repo root:
//
//	PYTHONPATH=tessera-hash/python python3 tessera-hash/examples/python/interop_encode.py \
//	    | go run ./tessera-hash/examples/go/interop
package main

import (
	"bufio"
	"fmt"
	"log"
	"os"

	tesserahash "github.com/barum/tessera/tessera-hash/go"
)

// Must match tessera-hash/examples/python/interop_encode.py exactly.
const (
	content   = "tessera-hash cross-language interop payload"
	tsMs      = 1_750_000_000_000
	counterID = 7
)

func main() {
	sc := bufio.NewScanner(os.Stdin)
	if !sc.Scan() {
		log.Fatal("expected one Crockford-encoded TesseraHash line on stdin")
	}
	h, err := tesserahash.DecodeCrockford(sc.Text())
	if err != nil {
		log.Fatalf("Crockford decode: %v", err)
	}
	if !tesserahash.Verify(h[:], []byte(content)) {
		log.Fatal("tail does not verify against the shared interop content")
	}
	recomputed, err := tesserahash.HashAt([]byte(content), tsMs, counterID)
	if err != nil {
		log.Fatal(err)
	}
	if recomputed != h {
		log.Fatal("HashAt(content, ts, counter) is not byte-identical to the Python hash")
	}
	fmt.Println("interop OK: Python-emitted TesseraHash verified and recomputed byte-identical in Go")
}
