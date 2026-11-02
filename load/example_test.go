package load_test

import (
	"fmt"
	"os"

	"github.com/Vulnetix/vdb-openapi/load"
	"github.com/Vulnetix/vdb-openapi/route"
)

func Example() {
	doc, err := load.LoadFile(os.DirFS("../testdata/coherence"), "petstore.swagger2.yaml", load.Options{})
	if err != nil {
		fmt.Println(err)
		return
	}
	for _, op := range doc.Operations {
		fmt.Println(op.Key, op.Security.State)
	}

	var ts []route.Template
	for _, op := range doc.Operations {
		for _, s := range doc.Servers {
			ts = append(ts, route.Template{Method: op.Method, Path: route.Join(s.BasePath, route.Path(op.PathTemplate)), Key: op.Key})
		}
	}
	t, ok := route.Compile(ts).Match("GET", "/v1/pets/42")
	fmt.Println(t.Key, ok)
	// Output:
	// GET /pets required
	// POST /pets required
	// GET /pets/{param} none
	// DELETE /pets/{param} optional
	// POST /pets/{param}/photo required
	// GET /pets/{param} true
}
