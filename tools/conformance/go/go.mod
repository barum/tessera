module conformance_runner

go 1.26

require (
	github.com/barum/tessera/tessera-hash/go v0.0.0
	github.com/barum/tessera/tessera-id/go v0.0.0
)

require (
	golang.org/x/crypto v0.51.0 // indirect
	golang.org/x/sys v0.44.0 // indirect
)

replace (
	github.com/barum/tessera/tessera-hash/go => ../../../tessera-hash/go
	github.com/barum/tessera/tessera-id/go => ../../../tessera-id/go
)
