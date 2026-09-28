package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"unicode"
)

// Каждый шаблон, который уходит в веб-интерфейс (tr, errf, logf), должен быть в enFormats,
// иначе в английском интерфейсе останется русский текст.
func TestAllTextsTranslated(t *testing.T) {
	files, _ := filepath.Glob("*.go")
	fset := token.NewFileSet()
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, f, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			var name string
			switch fn := call.Fun.(type) {
			case *ast.Ident:
				name = fn.Name
			case *ast.SelectorExpr:
				name = fn.Sel.Name
			}
			arg := -1
			switch name {
			case "tr", "errf":
				arg = 0
			case "logf":
				arg = 1
			}
			if arg < 0 || len(call.Args) <= arg {
				return true
			}
			if id, ok := call.Args[arg].(*ast.Ident); ok && id.Name == "format" {
				return true // logf и errf передают шаблон дальше в tr
			}
			format, ok := constString(call.Args[arg])
			if !ok {
				t.Errorf("%s: %s: шаблон должен быть строковой константой", fset.Position(call.Pos()), name)
				return true
			}
			if _, ok := enFormats[format]; !ok && hasCyrillic(format) {
				t.Errorf("%s: нет перевода для %q", fset.Position(call.Pos()), format)
			}
			return true
		})
	}
}

// constString — значение строкового литерала или их конкатенации.
func constString(e ast.Expr) (string, bool) {
	switch v := e.(type) {
	case *ast.BasicLit:
		if v.Kind != token.STRING {
			return "", false
		}
		s, err := strconv.Unquote(v.Value)
		return s, err == nil
	case *ast.BinaryExpr:
		if v.Op != token.ADD {
			return "", false
		}
		a, ok1 := constString(v.X)
		b, ok2 := constString(v.Y)
		return a + b, ok1 && ok2
	}
	return "", false
}

func hasCyrillic(s string) bool {
	for _, r := range s {
		if unicode.Is(unicode.Cyrillic, r) {
			return true
		}
	}
	return false
}

func TestTr(t *testing.T) {
	inner := errf("недопустимый порт %q", "x")
	got := tr("проверка %q: %v", "a.com", inner)
	if got.Ru != `проверка "a.com": недопустимый порт "x"` || got.En != `check "a.com": invalid port "x"` {
		t.Fatalf("%+v", got)
	}
	if e := errText(errf("узел %q: %v", "g", inner)); e.En != `node "g": invalid port "x"` {
		t.Fatalf("%+v", e)
	}
	for n, want := range map[int]string{1: "1 соединение", 3: "3 соединения", 5: "5 соединений", 11: "11 соединений", 21: "21 соединение", 112: "112 соединений"} {
		if got := sessions(n).Ru; got != want {
			t.Errorf("%d: %q", n, got)
		}
	}
	if sessions(1).En != "1 session" || sessions(2).En != "2 sessions" {
		t.Error(sessions(1), sessions(2))
	}
}
