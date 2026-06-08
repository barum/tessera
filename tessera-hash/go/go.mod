module tesserahash

go 1.26

require (
	golang.org/x/crypto v0.51.0
	tesseraid v0.0.0
)

require golang.org/x/sys v0.44.0 // indirect

replace tesseraid => ../../tessera-id/go
