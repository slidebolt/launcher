package main

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
)

// Config holds all resolved launcher configuration. It is a pure value type —
// computed once at startup from environment variables and passed explicitly to
// every function that needs it. There are no package-level globals.
type Config struct {
	// Network
	APIURL  string // http://host:port — used for health checks
	APIHost string // forwarded to gateway env
	APIPort string // forwarded to gateway env
	NATSURL string // nats://host:port — may be updated after runtime discovery

	// Service identity
	CorePluginID string

	// Paths — all derived from BuildDir
	BuildDir string
	BinDir   string
	LogDir   string
	PIDDir   string
	DataDir  string
	LockFile string
	PIDFile  string

	// Mode flags
	Prebuilt  bool
	StartNATS bool
}

// LoadConfig resolves all configuration from environment variables.
// Port "0" selects a random free port. Empty values use documented defaults.
func LoadConfig() Config {
	apiHost := envOr("LAUNCHER_API_HOST", "127.0.0.1")
	natsHost := envOr("LAUNCHER_NATS_HOST", "127.0.0.1")
	apiPort := resolvePort("LAUNCHER_API_PORT", "8082")
	natsPort := resolvePort("LAUNCHER_NATS_PORT", "4224")
	corePluginID := envOr("LAUNCHER_CORE_PLUGIN_ID", "gateway")
	buildDir := envOr("LAUNCHER_BUILD_DIR", ".build")

	return Config{
		APIURL:       fmt.Sprintf("http://%s:%s", apiHost, apiPort),
		APIHost:      apiHost,
		APIPort:      apiPort,
		NATSURL:      fmt.Sprintf("nats://%s:%s", natsHost, natsPort),
		CorePluginID: corePluginID,

		BuildDir: buildDir,
		BinDir:   filepath.Join(buildDir, "bin"),
		LogDir:   filepath.Join(buildDir, "logs"),
		PIDDir:   filepath.Join(buildDir, "pids"),
		DataDir:  filepath.Join(buildDir, "data"),
		LockFile: filepath.Join(buildDir, "launcher.lock"),
		PIDFile:  filepath.Join(buildDir, "launcher.pid"),

		Prebuilt:  isTruthy(os.Getenv("LAUNCHER_PREBUILT")),
		StartNATS: !isTruthy(os.Getenv("LAUNCHER_SKIP_NATS")),
	}
}

// envOr returns the trimmed environment value for key, or fallback if unset/empty.
func envOr(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

// isTruthy returns true for "1", "true", "yes", "on" (case-insensitive).
func isTruthy(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

// resolvePort returns the port string for the given env key, using fallback
// when the env var is unset. A value of "0" selects a random free port.
func resolvePort(key, fallback string) string {
	v := strings.TrimSpace(os.Getenv(key))
	switch v {
	case "":
		return fallback
	case "0":
		return randomFreePort()
	default:
		return v
	}
}

func randomFreePort() string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "0"
	}
	defer ln.Close()
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	return port
}
