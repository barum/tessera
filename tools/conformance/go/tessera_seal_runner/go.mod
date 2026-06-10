module tesseraseal_runner

go 1.26

require (
	github.com/barum/tessera/tessera-seal/go v0.0.0
	golang.org/x/crypto v0.51.0
)

require golang.org/x/sys v0.44.0 // indirect

replace github.com/barum/tessera/tessera-seal/go => ../../../../tessera-seal/go
