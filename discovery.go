package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// discoverPluginPaths returns the paths of all buildable plugin directories
// under root (containing both go.mod and main.go). Hidden dirs and dirs
// ending in ".del" are ignored.
func discoverPluginPaths(root string) []string {
	entries, _ := os.ReadDir(root)
	var paths []string
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		name := entry.Name()
		if strings.HasPrefix(name, ".") || strings.HasSuffix(name, ".del") {
			continue
		}
		path := filepath.Join(root, name)
		if isBuildable(path) {
			paths = append(paths, path)
		}
	}
	return paths
}

// discoverPluginBinaries returns the names of all files in root whose names
// start with "plugin-". These are the prebuilt plugin binaries.
func discoverPluginBinaries(root string) []string {
	entries, _ := os.ReadDir(root)
	var names []string
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasPrefix(entry.Name(), "plugin-") {
			names = append(names, entry.Name())
		}
	}
	return names
}

// validatePrebuiltBinaries reads manifestPath and confirms every listed binary
// exists under root. Returns a non-nil error listing any that are missing.
func validatePrebuiltBinaries(root, manifestPath string) error {
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		return fmt.Errorf("failed reading %s: %w", manifestPath, err)
	}
	var components []struct {
		ID     string `json:"id"`
		Binary string `json:"binary"`
	}
	if err := json.Unmarshal(data, &components); err != nil {
		return fmt.Errorf("failed parsing %s: %w", manifestPath, err)
	}
	var missing []string
	for _, c := range components {
		binary := strings.TrimSpace(c.Binary)
		if binary == "" {
			continue
		}
		if _, err := os.Stat(filepath.Join(root, binary)); err != nil {
			label := binary
			if id := strings.TrimSpace(c.ID); id != "" {
				label = id + "(" + binary + ")"
			}
			missing = append(missing, label)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("missing prebuilt binaries: %s", strings.Join(missing, ", "))
	}
	return nil
}

// isBuildable returns true if path contains both go.mod and main.go.
func isBuildable(path string) bool {
	_, errMod := os.Stat(filepath.Join(path, "go.mod"))
	_, errMain := os.Stat(filepath.Join(path, "main.go"))
	return errMod == nil && errMain == nil
}
