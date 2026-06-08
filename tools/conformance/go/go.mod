module conformance_runner

go 1.26

require (
	tesserahash v0.0.0
	tesseraid v0.0.0
)

require (
	golang.org/x/crypto v0.51.0 // indirect
	golang.org/x/sys v0.44.0 // indirect
)

replace (
	tesserahash => ../../../tessera-hash/go
	tesseraid => ../../../tessera-id/go
)
