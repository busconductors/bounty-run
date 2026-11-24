package runs

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// engineName is the engine executable's file name in every location searched.
const engineName = "bounty-run"

// ErrEngineNotFound means no engine binary exists in any searched location.
var ErrEngineNotFound = errors.New("bounty-run engine not found")

// OutputsRoot returns the directory runs are written under, creating it with
// mode 0700: $BOUNTY_OUTPUTS, else $XDG_DATA_HOME/bounty-run/outputs (with
// the XDG default ~/.local/share). An existing root with looser permissions is
// tightened to 0700, since runs hold findings and evidence.
func OutputsRoot() (string, error) {
	root := os.Getenv("BOUNTY_OUTPUTS")
	if root == "" {
		data := os.Getenv("XDG_DATA_HOME")
		if !filepath.IsAbs(data) { // the XDG spec says relative values are invalid
			home, err := os.UserHomeDir()
			if err != nil {
				return "", fmt.Errorf("outputs root: %w", err)
			}
			data = filepath.Join(home, ".local", "share")
		}
		root = filepath.Join(data, "bounty-run", "outputs")
	}
	root, err := filepath.Abs(root)
	if err != nil {
		return "", fmt.Errorf("outputs root: %w", err)
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return "", fmt.Errorf("outputs root: %w", err)
	}
	fi, err := os.Stat(root)
	if err != nil {
		return "", fmt.Errorf("outputs root: %w", err)
	}
	if !fi.IsDir() {
		return "", fmt.Errorf("outputs root %s is not a directory", root)
	}
	if fi.Mode().Perm() != 0o700 {
		if err := os.Chmod(root, 0o700); err != nil {
			return "", fmt.Errorf("outputs root: %w", err)
		}
	}
	return root, nil
}

// EngineBin locates the engine: $BOUNTY_ENGINE_DIR/bounty-run when that
// variable is set (an error if the file is missing, with no fallback), else
// the packaged locations beside this executable, else bounty-run on PATH.
func EngineBin() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		exe = ""
	}
	return resolveEngineBin(os.Getenv, exe, exec.LookPath)
}

func resolveEngineBin(getenv func(string) string, exe string, lookPath func(string) (string, error)) (string, error) {
	if d := getenv("BOUNTY_ENGINE_DIR"); d != "" {
		p := filepath.Join(d, engineName)
		if err := checkEngine(p); err != nil {
			return "", fmt.Errorf("BOUNTY_ENGINE_DIR: %w", err)
		}
		return p, nil
	}
	if exe != "" {
		dir := filepath.Dir(exe)
		for _, p := range []string{
			filepath.Join(dir, "engine", engineName),
			filepath.Join(dir, "..", "lib", "bounty-run", "engine", engineName),
		} {
			p = filepath.Clean(p)
			err := checkEngine(p)
			if err == nil {
				return p, nil
			}
			if !errors.Is(err, os.ErrNotExist) {
				return "", err // present but unusable: say so rather than run another engine
			}
		}
	}
	if p, err := lookPath(engineName); err == nil {
		return p, nil
	}
	return "", ErrEngineNotFound
}

// checkEngine reports whether p is an executable regular file.
func checkEngine(p string) error {
	fi, err := os.Stat(p)
	if err != nil {
		return err
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("engine %s is not a regular file", p)
	}
	if fi.Mode().Perm()&0o111 == 0 {
		return fmt.Errorf("engine %s is not executable", p)
	}
	return nil
}
