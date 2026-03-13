package main

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
)

// pluginEnv returns a merged map of env vars from the plugin's .env and
// .env.local files. Keys already present in the process environment take
// precedence; runtimeEnv (infrastructure vars) always wins over everything.
func pluginEnv(name string, runtimeEnv map[string]string) []string {
	fileEnv := loadPluginFileEnv(name)
	return mergedEnv(os.Environ(), fileEnv, runtimeEnv)
}

// loadPluginFileEnv reads .env and .env.local for name from the plugin source
// directory and the plugin config root (LAUNCHER_PLUGIN_CONFIG_ROOT or
// config/plugins/<name>).
func loadPluginFileEnv(name string) map[string]string {
	configRoot := envOr("LAUNCHER_PLUGIN_CONFIG_ROOT", filepath.Join("config", "plugins"))
	roots := []string{
		filepath.Join("plugins", name),
		filepath.Join(configRoot, name),
	}

	seen := map[string]struct{}{}
	out := make(map[string]string)
	for _, root := range roots {
		for _, base := range []string{".env", ".env.local"} {
			path := filepath.Join(root, base)
			if _, exists := seen[path]; exists {
				continue
			}
			seen[path] = struct{}{}
			vals, err := parseDotEnvFile(path)
			if err != nil {
				continue
			}
			for k, v := range vals {
				out[k] = v
			}
		}
	}
	return out
}

// parseDotEnvFile parses a KEY=VALUE file, stripping comments, blank lines,
// optional "export " prefixes, and surrounding quotes.
func parseDotEnvFile(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	out := make(map[string]string)
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimPrefix(line, "export ")
		line = strings.TrimSpace(line)

		i := strings.Index(line, "=")
		if i <= 0 {
			continue
		}
		key := strings.TrimSpace(line[:i])
		val := strings.Trim(strings.TrimSpace(line[i+1:]), `"'`)
		if key != "" {
			out[key] = val
		}
	}
	return out, sc.Err()
}

// mergedEnv builds a process env slice from three layers, in precedence order
// (highest → lowest):
//
//  1. runtimeEnv — infrastructure vars injected by the launcher (always wins)
//  2. base        — current process environment
//  3. fileEnv     — values from plugin .env files (fill in missing keys only)
func mergedEnv(base []string, fileEnv map[string]string, runtimeEnv map[string]string) []string {
	envMap := make(map[string]string, len(base))
	for _, kv := range base {
		if i := strings.Index(kv, "="); i > 0 {
			envMap[kv[:i]] = kv[i+1:]
		}
	}
	for k, v := range fileEnv {
		if _, exists := envMap[k]; !exists {
			envMap[k] = v
		}
	}
	for k, v := range runtimeEnv {
		envMap[k] = v
	}

	out := make([]string, 0, len(envMap))
	for k, v := range envMap {
		out = append(out, k+"="+v)
	}
	return out
}
