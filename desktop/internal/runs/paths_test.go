package runs

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func perm(t *testing.T, p string) os.FileMode {
	t.Helper()
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Mode().Perm()
}

func TestOutputsRootIs0700(t *testing.T) {
	t.Run("BOUNTY_OUTPUTS created 0700", func(t *testing.T) {
		want := filepath.Join(t.TempDir(), "a", "outputs")
		t.Setenv("BOUNTY_OUTPUTS", want)
		got, err := OutputsRoot()
		if err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Fatalf("root = %q, want %q", got, want)
		}
		if p := perm(t, got); p != 0o700 {
			t.Fatalf("mode = %o, want 700", p)
		}
	})
	t.Run("existing loose dir tightened", func(t *testing.T) {
		want := filepath.Join(t.TempDir(), "outputs")
		if err := os.Mkdir(want, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(want, 0o777); err != nil {
			t.Fatal(err)
		}
		t.Setenv("BOUNTY_OUTPUTS", want)
		if _, err := OutputsRoot(); err != nil {
			t.Fatal(err)
		}
		if p := perm(t, want); p != 0o700 {
			t.Fatalf("mode = %o, want 700", p)
		}
	})
	t.Run("XDG_DATA_HOME", func(t *testing.T) {
		xdg := t.TempDir()
		t.Setenv("BOUNTY_OUTPUTS", "")
		t.Setenv("XDG_DATA_HOME", xdg)
		got, err := OutputsRoot()
		if err != nil {
			t.Fatal(err)
		}
		if want := filepath.Join(xdg, "bounty-run", "outputs"); got != want {
			t.Fatalf("root = %q, want %q", got, want)
		}
		if p := perm(t, got); p != 0o700 {
			t.Fatalf("mode = %o, want 700", p)
		}
	})
	t.Run("XDG default under HOME", func(t *testing.T) {
		home := t.TempDir()
		t.Setenv("BOUNTY_OUTPUTS", "")
		t.Setenv("XDG_DATA_HOME", "")
		t.Setenv("HOME", home)
		got, err := OutputsRoot()
		if err != nil {
			t.Fatal(err)
		}
		if want := filepath.Join(home, ".local", "share", "bounty-run", "outputs"); got != want {
			t.Fatalf("root = %q, want %q", got, want)
		}
	})
	t.Run("relative XDG_DATA_HOME ignored", func(t *testing.T) {
		home := t.TempDir()
		t.Setenv("BOUNTY_OUTPUTS", "")
		t.Setenv("XDG_DATA_HOME", "rel/data")
		t.Setenv("HOME", home)
		got, err := OutputsRoot()
		if err != nil {
			t.Fatal(err)
		}
		if want := filepath.Join(home, ".local", "share", "bounty-run", "outputs"); got != want {
			t.Fatalf("root = %q, want %q", got, want)
		}
	})
	t.Run("not a directory", func(t *testing.T) {
		f := filepath.Join(t.TempDir(), "file")
		if err := os.WriteFile(f, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		t.Setenv("BOUNTY_OUTPUTS", f)
		if _, err := OutputsRoot(); err == nil {
			t.Fatal("a regular file was accepted as outputs root")
		}
	})
}

func writeExe(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
}

func TestEngineBinResolution(t *testing.T) {
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	noPath := func(string) (string, error) { return "", exec.ErrNotFound }

	t.Run("BOUNTY_ENGINE_DIR wins", func(t *testing.T) {
		d := t.TempDir()
		writeExe(t, filepath.Join(d, "bounty-run"))
		exe := filepath.Join(t.TempDir(), "app")
		writeExe(t, filepath.Join(filepath.Dir(exe), "engine", "bounty-run"))
		got, err := resolveEngineBin(env(map[string]string{"BOUNTY_ENGINE_DIR": d}), exe, noPath)
		if err != nil || got != filepath.Join(d, "bounty-run") {
			t.Fatalf("got %q, %v", got, err)
		}
	})
	t.Run("BOUNTY_ENGINE_DIR missing file has no fallback", func(t *testing.T) {
		exe := filepath.Join(t.TempDir(), "app")
		writeExe(t, filepath.Join(filepath.Dir(exe), "engine", "bounty-run"))
		lp := func(string) (string, error) { return "/usr/bin/bounty-run", nil }
		_, err := resolveEngineBin(env(map[string]string{"BOUNTY_ENGINE_DIR": t.TempDir()}), exe, lp)
		if err == nil {
			t.Fatal("missing engine under BOUNTY_ENGINE_DIR fell back")
		}
	})
	t.Run("exedir/engine", func(t *testing.T) {
		root := t.TempDir()
		exe := filepath.Join(root, "bin", "app")
		want := filepath.Join(root, "bin", "engine", "bounty-run")
		writeExe(t, want)
		writeExe(t, filepath.Join(root, "lib", "bounty-run", "engine", "bounty-run"))
		got, err := resolveEngineBin(env(nil), exe, noPath)
		if err != nil || got != want {
			t.Fatalf("got %q, %v; want %q", got, err, want)
		}
	})
	t.Run("exedir/../lib/bounty-run/engine", func(t *testing.T) {
		root := t.TempDir()
		exe := filepath.Join(root, "bin", "app")
		want := filepath.Join(root, "lib", "bounty-run", "engine", "bounty-run")
		writeExe(t, want)
		got, err := resolveEngineBin(env(nil), exe, noPath)
		if err != nil || got != want {
			t.Fatalf("got %q, %v; want %q", got, err, want)
		}
	})
	t.Run("PATH fallback", func(t *testing.T) {
		exe := filepath.Join(t.TempDir(), "app")
		lp := func(name string) (string, error) {
			if name != "bounty-run" {
				t.Fatalf("looked up %q", name)
			}
			return "/opt/x/bounty-run", nil
		}
		got, err := resolveEngineBin(env(nil), exe, lp)
		if err != nil || got != "/opt/x/bounty-run" {
			t.Fatalf("got %q, %v", got, err)
		}
	})
	t.Run("nothing found", func(t *testing.T) {
		exe := filepath.Join(t.TempDir(), "app")
		_, err := resolveEngineBin(env(nil), exe, noPath)
		if !errors.Is(err, ErrEngineNotFound) {
			t.Fatalf("err = %v, want ErrEngineNotFound", err)
		}
	})
	t.Run("directory is not an engine", func(t *testing.T) {
		root := t.TempDir()
		exe := filepath.Join(root, "app")
		if err := os.MkdirAll(filepath.Join(root, "engine", "bounty-run"), 0o755); err != nil {
			t.Fatal(err)
		}
		_, err := resolveEngineBin(env(nil), exe, noPath)
		if err == nil {
			t.Fatal("a directory was accepted as the engine")
		}
	})
	t.Run("EngineBin uses the environment", func(t *testing.T) {
		d := t.TempDir()
		writeExe(t, filepath.Join(d, "bounty-run"))
		t.Setenv("BOUNTY_ENGINE_DIR", d)
		got, err := EngineBin()
		if err != nil || got != filepath.Join(d, "bounty-run") {
			t.Fatalf("got %q, %v", got, err)
		}
	})
}
