<p align="center">
  <img src="pix.svg" alt="Pix, the Vulnetix mascot" width="110">
</p>

# vdb-openapi

A Go module that reads Swagger 2.0, OpenAPI 3.0 and OpenAPI 3.1 documents into one data contract. It is for every Vulnetix service that handles API descriptions: the CLI, vdb-api, vdb-site, cloudscan and the processors. A consumer gets the same `oas.Document` whatever version the file was written in, and never imports a parser library or branches on spec version.

## Install

```sh
go get github.com/Vulnetix/vdb-openapi@latest
```

## Usage

```go
import (
    "github.com/Vulnetix/vdb-openapi/load"
    "github.com/Vulnetix/vdb-openapi/route"
)

doc, err := load.LoadFile(os.DirFS("."), "api/openapi.yaml", load.Options{})
if err != nil {
    return err
}
for _, op := range doc.Operations {
    fmt.Println(op.Key, op.Security.State) // GET /pets/{param} required
}

// Match live request paths (a log line, a sensor event) to operations.
var ts []route.Template
for _, op := range doc.Operations {
    for _, s := range doc.Servers {
        ts = append(ts, route.Template{Method: op.Method, Path: route.Join(s.BasePath, route.Path(op.PathTemplate)), Key: op.Key})
    }
}
m := route.Compile(ts)
t, ok := m.Match("GET", "/v1/pets/42") // t.Key == "GET /pets/{param}"
```

## Packages

| Package | What it does |
|---|---|
| `oas` | The contract types and `ContractVersion`. |
| `load` | Detects, parses and converts a document. Follows `$ref`s through an `fs.FS` or a `Resolver` you pass; never opens a network connection itself. |
| `route` | The one route key (`GET /users/{param}`) shared with code routes from `vulnetix analyze`, plus a matcher whose serialised form other languages can rebuild. |
| `diff` | Changes between two versions, each flagged breaking and/or a security regression. |
| `detect` | Spec file names, framework generators and the well-known probe paths (`detect/probepaths.json`). |
| `lint` | Structural checks that break correlation or testing. |
| `contract` | `contract.schema.json`, the JSON Schema of `oas.Document`, generated from the Go types. |

## Configuration

`load.Options` sets the document's `Path`, the `FS` for relative `$ref`s, a `Resolver` for absolute URLs, and `Limits`. The default limits are 32 MiB, 4,000,000 nodes counted with YAML aliases expanded, depth 256, and 64 referenced documents. A document past a limit returns `load.ErrTooLarge`, `load.ErrTooMany` or `load.ErrTooDeep`.

What the contract cannot carry (JSON Schema `if`/`then`, `prefixItems`, an external `$ref` with no resolver, an unknown spec version) is listed in `Document.Losses` with a JSON pointer. A consumer that shows a document should say it is partial when `Losses` is not empty.

## Tests

```sh
go test ./...
go test ./load -run '^$' -fuzz FuzzLoad -fuzztime 60s
go run ./cmd/genschema && git diff --exit-code contract/contract.schema.json
```

`TestCoherence` reads `testdata/coherence/petstore.*` (one API written in all three versions) and requires byte-identical contract JSON apart from `Source`. The golden output is `testdata/coherence/petstore.contract.json`; regenerate it with `go test ./load -update` and review the diff.

The route cases in `testdata/route/` are shared: cli, vdb-site, siem and website keep byte copies and run them. Change them here first.

## Contributing

Commits follow Conventional Commits; the auto-version workflow tags a release from them. A change to a JSON field name in `oas` is breaking: bump `oas.ContractVersion`'s major and use a `!` commit.

## License

Apache-2.0.
