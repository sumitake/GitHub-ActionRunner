package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strconv"
	"testing"
)

func TestLinuxSeccompArchitectureGuardSkipsKillOnlyOnExactMatch(t *testing.T) {
	tree := parseLinuxSandbox(t)
	var guards [][2]uint64
	ast.Inspect(tree, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok || len(call.Args) != 4 {
			return true
		}
		function, ok := call.Fun.(*ast.Ident)
		if !ok || function.Name != "jump" {
			return true
		}
		architecture, ok := call.Args[1].(*ast.Ident)
		if !ok || architecture.Name != "architecture" {
			return true
		}
		onTrue, trueOK := integerLiteral(call.Args[2])
		onFalse, falseOK := integerLiteral(call.Args[3])
		if trueOK && falseOK {
			guards = append(guards, [2]uint64{onTrue, onFalse})
		}
		return true
	})
	if len(guards) != 1 || guards[0] != [2]uint64{1, 0} {
		t.Fatalf(
			"architecture guard jumps=%v, want exact match to skip kill",
			guards,
		)
	}
}

func TestLinuxSeccompPrctlBranchReloadsSyscallNumber(t *testing.T) {
	tree := parseLinuxSandbox(t)
	found := false
	ast.Inspect(tree, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok || callName(call) != "append" {
			return true
		}
		for _, argument := range call.Args {
			jump, ok := argument.(*ast.CallExpr)
			if !ok || callName(jump) != "jump" ||
				len(jump.Args) != 4 ||
				!isUint32UnixConstant(jump.Args[1], "SYS_PRCTL") {
				continue
			}
			found = true
			if !isSyscallNumberReload(call.Args[len(call.Args)-1]) {
				t.Error("allowed prctl branch does not reload syscall number")
			}
		}
		return true
	})
	if !found {
		t.Fatal("PRCTL seccomp branch not found")
	}
}

func parseLinuxSandbox(t *testing.T) *ast.File {
	t.Helper()
	tree, err := parser.ParseFile(
		token.NewFileSet(),
		"sandbox_linux.go",
		nil,
		0,
	)
	if err != nil {
		t.Fatalf("parse sandbox_linux.go: %v", err)
	}
	return tree
}

func callName(call *ast.CallExpr) string {
	identifier, ok := call.Fun.(*ast.Ident)
	if !ok {
		return ""
	}
	return identifier.Name
}

func isUint32UnixConstant(expression ast.Expr, name string) bool {
	conversion, ok := expression.(*ast.CallExpr)
	if !ok || callName(conversion) != "uint32" || len(conversion.Args) != 1 {
		return false
	}
	selector, ok := conversion.Args[0].(*ast.SelectorExpr)
	if !ok || selector.Sel.Name != name {
		return false
	}
	pkg, ok := selector.X.(*ast.Ident)
	return ok && pkg.Name == "unix"
}

func isSyscallNumberReload(expression ast.Expr) bool {
	statement, ok := expression.(*ast.CallExpr)
	if !ok || callName(statement) != "statement" ||
		len(statement.Args) != 2 {
		return false
	}
	loadWord, ok := statement.Args[0].(*ast.Ident)
	if !ok || loadWord.Name != "loadWord" {
		return false
	}
	offset, ok := integerLiteral(statement.Args[1])
	return ok && offset == 0
}

func integerLiteral(expression ast.Expr) (uint64, bool) {
	literal, ok := expression.(*ast.BasicLit)
	if !ok || literal.Kind != token.INT {
		return 0, false
	}
	value, err := strconv.ParseUint(literal.Value, 0, 8)
	return value, err == nil
}
