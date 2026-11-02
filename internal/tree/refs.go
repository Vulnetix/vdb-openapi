package tree

import (
	"errors"
	"fmt"
	"io/fs"
	"path"
	"strings"
)

// Resolver fetches a document named by an absolute URL. The module never
// opens a network connection itself: a caller that wants remote $refs
// passes one, and owns the SSRF rules that come with it.
type Resolver interface {
	Fetch(url string) ([]byte, error)
}

// Doc is one parsed document and where it came from.
type Doc struct {
	Root any
	// Location is the file path within FS, or an absolute URL, or "" for
	// the in-memory root document.
	Location string
}

// Refs resolves $ref values. It caches every external document it loads.
type Refs struct {
	FS       fs.FS
	Resolver Resolver
	Limits   Limits
	MaxDocs  int

	cache map[string]*Doc
}

var ErrExternalRef = errors.New("external reference not followed")

// Resolve follows ref relative to from and returns the target value, the
// document it lives in and the pointer within it. Chained refs (a $ref to
// a $ref) are followed up to 32 hops.
func (r *Refs) Resolve(from *Doc, ref string) (any, *Doc, string, error) {
	doc := from
	cur := ref
	for hop := 0; hop < 32; hop++ {
		loc, ptr := splitRef(cur)
		if loc != "" {
			d, err := r.load(doc, loc)
			if err != nil {
				return nil, nil, "", err
			}
			doc = d
		}
		v, err := Pointer(doc.Root, ptr)
		if err != nil {
			return nil, nil, "", err
		}
		if m, ok := v.(map[string]any); ok {
			if next, ok := m["$ref"].(string); ok {
				cur = next
				continue
			}
		}
		return v, doc, ptr, nil
	}
	return nil, nil, "", fmt.Errorf("reference chain from %q is longer than 32 hops", ref)
}

func splitRef(ref string) (string, string) {
	if i := strings.Index(ref, "#"); i >= 0 {
		return ref[:i], ref[i+1:]
	}
	return ref, ""
}

func (r *Refs) load(from *Doc, loc string) (*Doc, error) {
	key, remote := r.locate(from, loc)
	if r.cache == nil {
		r.cache = map[string]*Doc{}
	}
	if d, ok := r.cache[key]; ok {
		return d, nil
	}
	max := r.MaxDocs
	if max <= 0 {
		max = 64
	}
	if len(r.cache) >= max {
		return nil, fmt.Errorf("more than %d referenced documents", max)
	}
	var data []byte
	var err error
	switch {
	case remote && r.Resolver != nil:
		data, err = r.Resolver.Fetch(key)
	case remote:
		return nil, fmt.Errorf("%w: %s", ErrExternalRef, key)
	case r.FS != nil:
		data, err = fs.ReadFile(r.FS, key)
	default:
		return nil, fmt.Errorf("%w: %s (no file system given)", ErrExternalRef, key)
	}
	if err != nil {
		return nil, err
	}
	root, _, err := Parse(data, r.Limits)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", key, err)
	}
	d := &Doc{Root: root, Location: key}
	r.cache[key] = d
	return d, nil
}

// locate turns a reference location into a cache key, relative to the
// document it appears in.
func (r *Refs) locate(from *Doc, loc string) (string, bool) {
	if isURL(loc) {
		return loc, true
	}
	if from != nil && isURL(from.Location) {
		base := from.Location
		if i := strings.LastIndex(base, "/"); i >= 0 {
			base = base[:i+1]
		}
		return base + loc, true
	}
	dir := "."
	if from != nil && from.Location != "" {
		dir = path.Dir(from.Location)
	}
	return path.Clean(path.Join(dir, loc)), false
}

func isURL(s string) bool {
	return strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://")
}
