package bridge

import (
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

const wailsModule = "github.com/wailsapp/wails"

// wailsImporters returns the slash-separated paths, relative to root, of Go
// files importing Wails. Build tags are ignored so no variant can hide one.
func wailsImporters(t *testing.T, root string) []string {
	t.Helper()
	var found []string
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if name := entry.Name(); path != root && (name == "frontend" || name == "bin") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		for _, spec := range file.Imports {
			imported, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				return err
			}
			if imported == wailsModule || strings.HasPrefix(imported, wailsModule+"/") {
				rel, err := filepath.Rel(root, path)
				if err != nil {
					return err
				}
				found = append(found, filepath.ToSlash(rel))
				break
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
	return found
}

func TestNoWailsImportOutsideBridge(t *testing.T) {
	importers := wailsImporters(t, filepath.Join("..", ".."))
	inBridge := 0
	for _, path := range importers {
		if strings.HasPrefix(path, "internal/bridge/") {
			inBridge++
			continue
		}
		t.Errorf("%s imports Wails; only internal/bridge may", path)
	}
	if inBridge == 0 {
		t.Error("no Wails import under internal/bridge; the boundary check is vacuous")
	}
}
