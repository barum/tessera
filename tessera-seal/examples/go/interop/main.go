// Interop, decrypt side: consume the four hex lines emitted by the Python
// encrypt side (../../python/interop_encrypt.py prints keypair seed, AD —
// a TesseraID — envelope, and plaintext), derive the same keypair from the
// seed, decrypt the envelope under the same AD, and assert the plaintext.
//
// Run from the repo root:
//
//	PYTHONPATH=tessera-id/python:tessera-seal/python \
//	    python3 tessera-seal/examples/python/interop_encrypt.py \
//	    | go run ./tessera-seal/examples/go/interop
package main

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"fmt"
	"log"
	"os"

	tesseraseal "github.com/barum/tessera/tessera-seal/go"
)

func main() {
	sc := bufio.NewScanner(os.Stdin)
	sc.Buffer(make([]byte, 0, 1<<20), 1<<20) // envelope hex line is ~3.3 KB
	readHex := func(what string) []byte {
		if !sc.Scan() {
			log.Fatalf("expected 4 hex lines (seed, ad, envelope, plaintext); missing %s", what)
		}
		b, err := hex.DecodeString(sc.Text())
		if err != nil {
			log.Fatalf("bad hex for %s: %v", what, err)
		}
		return b
	}
	seed := readHex("seed")           // FIPS 203 d || z (64 bytes)
	ad := readHex("ad")               // 41-byte TesseraID
	envelope := readHex("envelope")   // suite 0x01 envelope sealed in Python
	plaintext := readHex("plaintext") // expected decrypt output

	priv, _, err := tesseraseal.GenerateKeypairFromSeed(seed, tesseraseal.SuiteMLKEM1024AESGCM)
	if err != nil {
		log.Fatal(err)
	}
	got, err := tesseraseal.Decrypt(envelope, priv, ad)
	if err != nil {
		log.Fatalf("decrypt of Python-sealed envelope failed: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		log.Fatal("plaintext mismatch: Go decrypt disagrees with Python encrypt")
	}
	fmt.Println("interop OK: sealed in Python, opened in Go (TesseraID-as-AD verified)")
}
