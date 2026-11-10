package main

// VERDICT-AUTH-001 (#28): structural guard for the "one detection authority"
// contract. Go Nose is acquisition-only — it frames evidence and reports it.
// The detection verdict fields on the wire (`EventType == TypeMatch`, a rule
// id, a severity ordinal) belong to Zig, which recomputes them from the bytes
// it actually received.
//
// This test reads the package source instead of behaviour on purpose: the
// failure mode it prevents is a *future* producer quietly reintroducing a
// verdict, which no runtime test would catch because the classifier would be
// dormant in the shipped configuration until someone wired it back in.
//
// Two files are exempt because they ARE the wire codec and its FFI mirror:
//   - canonical.go: Serialize/Deserialize must move every frozen field,
//     including the verdict fields, byte for byte.
//   - golden_path_ffi.go: decodes a frame to compare it against Zig's view.
// Neither decides anything; both must keep copying the fields verbatim.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// verdictCodecFiles may read and write the verdict fields: they transport the
// frozen contract, they never author a verdict.
var verdictCodecFiles = map[string]bool{
	"canonical.go":       true,
	"golden_path_ffi.go": true,
}

// verdictClaimTypes are the event-type ordinals that assert a detection or an
// enforcement outcome. A live producer may never emit them.
var verdictClaimTypes = map[string]bool{
	"TypeMatch": true,
}

func TestNoAcquisitionFileAuthorsADetectionVerdict(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}

	fset := token.NewFileSet()
	checked := 0
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		if verdictCodecFiles[name] {
			continue
		}
		path := filepath.Join(".", name)
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		checked++
		ast.Inspect(file, func(n ast.Node) bool {
			switch node := n.(type) {
			case *ast.AssignStmt:
				for _, lhs := range node.Lhs {
					sel, ok := lhs.(*ast.SelectorExpr)
					if !ok {
						continue
					}
					switch sel.Sel.Name {
					case "EventType", "RuleID", "Severity":
						t.Errorf("%s assigns %s outside the wire codec: acquisition tiers report evidence, Zig owns the verdict",
							fset.Position(node.Pos()).String(), sel.Sel.Name)
					}
				}
			case *ast.KeyValueExpr:
				key, ok := node.Key.(*ast.Ident)
				if !ok {
					return true
				}
				switch key.Name {
				case "EventType":
					if ident, ok := node.Value.(*ast.Ident); ok && verdictClaimTypes[ident.Name] {
						t.Errorf("%s emits %s from an acquisition producer",
							fset.Position(node.Pos()).String(), ident.Name)
					}
				case "RuleID", "Severity":
					if !isZeroLiteral(node.Value) {
						t.Errorf("%s sets %s to a nonzero value: acquisition severity/rule ids are claims, not evidence",
							fset.Position(node.Pos()).String(), key.Name)
					}
				}
			}
			return true
		})
	}

	if checked < 10 {
		t.Fatalf("guard inspected only %d files; the scan is broken, not the code", checked)
	}
}

// isZeroLiteral is true only for a plain `0` integer literal: anything else
// (a variable, a call, a computed value) is a claim the producer looked up
// somewhere, and the guard refuses to infer that it is harmless.
func isZeroLiteral(expr ast.Expr) bool {
	lit, ok := expr.(*ast.BasicLit)
	return ok && lit.Kind == token.INT && lit.Value == "0"
}
