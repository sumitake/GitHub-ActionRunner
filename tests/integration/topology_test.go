package integration_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

const (
	conformanceImportPath = "github.com/sumitake/portable-ghar/internal/conformance"
	testenvImportPath     = "github.com/sumitake/portable-ghar/tests/integration/testenv"
	effectEntrypointName  = "TestPortableGHARConformance"
)

type effectReference struct {
	file     string
	function string
	symbol   string
}

func TestSingleEffectEntrypointTopology(t *testing.T) {
	t.Parallel()

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read integration package: %v", err)
	}

	files := token.NewFileSet()
	var (
		entrypointFiles []string
		references      []effectReference
	)
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") {
			continue
		}
		path := filepath.Clean(entry.Name())
		source, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		file, err := parser.ParseFile(
			files,
			path,
			source,
			parser.ParseComments,
		)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}

		aliases := importAliases(t, path, file)
		for _, declaration := range file.Decls {
			function, ok := declaration.(*ast.FuncDecl)
			if !ok || function.Recv != nil {
				continue
			}
			if function.Name.Name == effectEntrypointName {
				entrypointFiles = append(entrypointFiles, path)
				if !hasIntegrationBuildConstraint(file) {
					t.Errorf(
						"%s must be guarded by //go:build integration",
						path,
					)
				}
			}
			if function.Body == nil {
				continue
			}
			ast.Inspect(function.Body, func(node ast.Node) bool {
				call, ok := node.(*ast.CallExpr)
				if !ok {
					return true
				}
				selector, ok := call.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				identifier, ok := selector.X.(*ast.Ident)
				if !ok {
					return true
				}
				importPath := aliases[identifier.Name]
				if importPath == testenvImportPath &&
					selector.Sel.Name == "StartDockerFixture" {
					references = append(references, effectReference{
						file:     path,
						function: function.Name.Name,
						symbol:   "testenv.StartDockerFixture",
					})
				}
				if importPath == conformanceImportPath &&
					selector.Sel.Name == "Run" {
					references = append(references, effectReference{
						file:     path,
						function: function.Name.Name,
						symbol:   "conformance.Run",
					})
				}
				return true
			})
		}
	}

	if len(entrypointFiles) != 1 {
		t.Errorf(
			"effect entrypoints = %d (%v), want exactly %s",
			len(entrypointFiles),
			entrypointFiles,
			effectEntrypointName,
		)
	}

	assertSingleEffectReference(
		t,
		references,
		"testenv.StartDockerFixture",
	)
	assertSingleEffectReference(t, references, "conformance.Run")
	for _, reference := range references {
		if reference.function != effectEntrypointName {
			t.Errorf(
				"%s in %s:%s, want sole effect entrypoint %s",
				reference.symbol,
				reference.file,
				reference.function,
				effectEntrypointName,
			)
		}
	}
}

func importAliases(
	t *testing.T,
	path string,
	file *ast.File,
) map[string]string {
	t.Helper()

	aliases := make(map[string]string)
	for _, spec := range file.Imports {
		importPath, err := strconv.Unquote(spec.Path.Value)
		if err != nil {
			t.Fatalf("unquote import in %s: %v", path, err)
		}
		if importPath != conformanceImportPath &&
			importPath != testenvImportPath {
			continue
		}
		if spec.Name != nil {
			if spec.Name.Name == "." || spec.Name.Name == "_" {
				t.Fatalf(
					"%s imports effect authority %s as %q",
					path,
					importPath,
					spec.Name.Name,
				)
			}
			aliases[spec.Name.Name] = importPath
			continue
		}
		aliases[filepath.Base(importPath)] = importPath
	}
	return aliases
}

func hasIntegrationBuildConstraint(file *ast.File) bool {
	for _, group := range file.Comments {
		for _, comment := range group.List {
			if comment.Text == "//go:build integration" {
				return true
			}
		}
	}
	return false
}

func assertSingleEffectReference(
	t *testing.T,
	references []effectReference,
	symbol string,
) {
	t.Helper()

	var matches []effectReference
	for _, reference := range references {
		if reference.symbol == symbol {
			matches = append(matches, reference)
		}
	}
	if len(matches) != 1 {
		t.Errorf("%s references = %d (%v), want exactly 1", symbol, len(matches), matches)
	}
}
