//go:build !production

package main

import (
	"errors"
	"io/fs"
)

// Keeps go test and go vet independent of a built frontend.
func frontendAssets() (fs.FS, error) {
	return nil, errors.New("frontend assets are embedded only in production builds; run: wails3 task build")
}
