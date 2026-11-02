// Package load reads an OpenAPI or Swagger document into the oas contract.
//
//	doc, err := load.Load(data, load.Options{Path: "api/openapi.yaml"})
//
// Load never opens a network connection. External $refs are followed
// through the FS (relative files) or the Resolver (absolute URLs) the
// caller passes; without them each external ref is recorded as a Loss.
package load

import (
	"crypto/sha256"
	"encoding/hex"
	"io/fs"

	"github.com/Vulnetix/vdb-openapi/internal/convert"
	"github.com/Vulnetix/vdb-openapi/internal/tree"
	"github.com/Vulnetix/vdb-openapi/oas"
)

// Resolver fetches an absolute URL for an external $ref. The caller owns
// SSRF protection, timeouts and size limits for what it fetches.
type Resolver interface {
	Fetch(url string) ([]byte, error)
}

// Limits bound the work one document may cause. Zero fields take the
// defaults.
type Limits struct {
	MaxBytes int
	MaxNodes int
	MaxDepth int
	// MaxDocs caps how many external documents $refs may pull in.
	MaxDocs int
}

// Options configure one read.
type Options struct {
	// Path is the document's location within FS, used for relative $refs
	// and reported in Source.Path.
	Path     string
	FS       fs.FS
	Resolver Resolver
	Limits   Limits
}

// ErrNotSpec is returned for a document with neither a swagger nor an
// openapi key at the root.
var ErrNotSpec = convert.ErrNotSpec

// Errors returned for documents past the limits.
var (
	ErrTooLarge = tree.ErrTooLarge
	ErrTooMany  = tree.ErrTooMany
	ErrTooDeep  = tree.ErrTooDeep
)

func (o Options) limits() tree.Limits {
	l := tree.DefaultLimits
	if o.Limits.MaxBytes > 0 {
		l.MaxBytes = o.Limits.MaxBytes
	}
	if o.Limits.MaxNodes > 0 {
		l.MaxNodes = o.Limits.MaxNodes
	}
	if o.Limits.MaxDepth > 0 {
		l.MaxDepth = o.Limits.MaxDepth
	}
	return l
}

// Load reads one document.
func Load(data []byte, opt Options) (*oas.Document, error) {
	lim := opt.limits()
	root, enc, err := tree.Parse(data, lim)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(data)
	refs := &tree.Refs{FS: opt.FS, Limits: lim, MaxDocs: opt.Limits.MaxDocs}
	if opt.Resolver != nil {
		refs.Resolver = opt.Resolver
	}
	doc := &tree.Doc{Root: root}
	if opt.FS != nil {
		doc.Location = opt.Path
	}
	return convert.Document(doc, refs, oas.Source{
		Encoding: enc,
		SHA256:   hex.EncodeToString(sum[:]),
		Path:     opt.Path,
	})
}

// LoadFile reads name from fsys; relative $refs resolve against it.
func LoadFile(fsys fs.FS, name string, opt Options) (*oas.Document, error) {
	data, err := fs.ReadFile(fsys, name)
	if err != nil {
		return nil, err
	}
	opt.FS, opt.Path = fsys, name
	return Load(data, opt)
}

// Sniff reports whether data looks like a Swagger or OpenAPI document,
// and which, without converting it. It parses the document, so it is
// bounded by the same limits.
func Sniff(data []byte, opt Options) (oas.Format, string, bool) {
	root, _, err := tree.Parse(data, opt.limits())
	if err != nil {
		return "", "", false
	}
	f, v, err := convert.Detect(root)
	return f, v, err == nil
}
