// Command genschema writes contract/contract.schema.json from package oas.
package main

import (
	"log"
	"os"

	"github.com/Vulnetix/vdb-openapi/contract"
)

func main() {
	if err := os.WriteFile("contract/contract.schema.json", contract.Generate(), 0o644); err != nil {
		log.Fatal(err)
	}
}
