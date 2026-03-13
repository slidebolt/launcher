package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Build compiles the Go package at srcPath and writes the binary to
// filepath.Join(outDir, name). It detects a go.work file in the current
// directory and sets GOWORK accordingly so monorepo replace directives work.
func Build(name, srcPath, outDir string) error {
	out, err := filepath.Abs(filepath.Join(outDir, name))
	if err != nil {
		return err
	}

	cmd := exec.Command("go", "build", "-o", out, ".")
	cmd.Dir = srcPath
	cmd.Env = append(os.Environ(), "GOWORK="+resolveGoWork())

	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%s", strings.TrimSpace(string(output)))
	}
	return nil
}

// resolveGoWork returns the absolute path to go.work if one exists in the
// current directory, or "auto" to let the Go toolchain decide.
func resolveGoWork() string {
	if abs, err := filepath.Abs("go.work"); err == nil {
		if _, err := os.Stat(abs); err == nil {
			return abs
		}
	}
	return "auto"
}
