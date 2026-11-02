package contract_test

import (
	"bytes"
	"testing"

	"github.com/Vulnetix/vdb-openapi/contract"
)

// The committed schema must match the Go types. Run `go run ./cmd/genschema`
// after changing package oas.
func TestSchemaIsCurrent(t *testing.T) {
	if !bytes.Equal(contract.Schema(), contract.Generate()) {
		t.Fatal("contract/contract.schema.json is stale; run go run ./cmd/genschema")
	}
}
