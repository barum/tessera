module tesseraseal_runner

go 1.26

require (
	golang.org/x/crypto v0.51.0
	tesseraseal v0.0.0
)

require golang.org/x/sys v0.44.0 // indirect

replace tesseraseal => ../../../../tessera-seal/go
