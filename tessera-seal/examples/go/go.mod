// Example-only module: resolved against the sibling tessera-seal and
// tessera-id Go modules via the repo-root go.work workspace. Run from the
// repo root:
//     go run ./tessera-seal/examples/go
module github.com/barum/tessera/tessera-seal/examples/go

go 1.26

require (
	github.com/barum/tessera/tessera-id/go v0.0.0
	github.com/barum/tessera/tessera-seal/go v0.0.0
)
