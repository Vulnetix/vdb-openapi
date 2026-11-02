# Notes for coding agents

This module is the only place a Vulnetix service reads an OpenAPI or Swagger document. Keep it that way.

- **One contract for every version.** A version difference is settled in `internal/convert` and nowhere else. `TestCoherence` must stay byte-identical across `testdata/coherence/petstore.*`; when you add a field, add it to all three inputs.
- **Unknown is not none.** `SecurityUnspecified` (nothing declared) is never `SecurityNone` (declared as no authentication), and an unset limit is `nil`, never `0`.
- **Say what was dropped.** A construct the summary cannot hold becomes a `Loss` with a JSON pointer, never a silent skip.
- **No network.** `load` follows remote `$ref`s only through a caller's `Resolver`. Do not add an HTTP client.
- **Caps stay on.** Every parse goes through `internal/tree` with its limits. Do not call `yaml.Unmarshal` into Go values anywhere else.
- **Pinned copies.** `testdata/route/*.json` and `detect/probepaths.json` are byte-copied into cli, vdb-site, siem and website. Change them here, then in each consumer.
- **Contract changes.** After changing `oas`, run `go run ./cmd/genschema` and `go test ./load -update`, and review both diffs. Renaming or removing a JSON field bumps `oas.ContractVersion`'s major.
- **No third-party types in the contract.** Parser and YAML types stay internal.
