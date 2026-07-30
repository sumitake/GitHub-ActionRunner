package conformance_test

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

func TestConformancePackageDependencyDirection(t *testing.T) {
	t.Parallel()

	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	directory := filepath.Dir(filename)
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	for _, entry := range entries {
		if entry.IsDir() ||
			!strings.HasSuffix(entry.Name(), ".go") ||
			strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		filename := filepath.Join(directory, entry.Name())
		file, err := parser.ParseFile(
			token.NewFileSet(),
			filename,
			nil,
			parser.ImportsOnly,
		)
		if err != nil {
			t.Fatalf("ParseFile %s: %v", entry.Name(), err)
		}
		for _, imported := range file.Imports {
			path, err := strconv.Unquote(imported.Path.Value)
			if err != nil {
				t.Fatalf("unquote import: %v", err)
			}
			if path == "github.com/sumitake/portable-ghar/internal/controller" ||
				path == "github.com/sumitake/portable-ghar/tests/integration/testenv" {
				t.Fatalf("forbidden conformance import %q", path)
			}
		}
	}
}
