// Package testhelpers provides utilities for launcher integration tests
package testhelpers

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// LauncherProcess represents a running launcher instance
type LauncherProcess struct {
	Cmd     *exec.Cmd
	Env     map[string]string
	TempDir string
	owned   bool
}

// StartLauncher starts the launcher with given environment variables
func StartLauncher(t *testing.T, env map[string]string, args ...string) *LauncherProcess {
	t.Helper()

	// Create temp directory for isolation unless caller provided one.
	tempDir := env["LAUNCHER_WORKDIR"]
	owned := false
	if tempDir == "" {
		var err error
		tempDir, err = os.MkdirTemp("", "launcher-test-*")
		if err != nil {
			t.Fatalf("Failed to create temp dir: %v", err)
		}
		owned = true
	}

	// Build launcher binary if not exists
	launcherBin := filepath.Join(tempDir, "launcher")
	buildCmd := exec.Command("go", "build", "-o", launcherBin, ".")
	buildCmd.Dir = "/home/gavin/work/sb/work/raw/launcher"
	if output, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("Failed to build launcher: %v\n%s", err, output)
	}

	// Prepare command
	cmdArgs := append([]string{}, args...)
	cmd := exec.Command(launcherBin, cmdArgs...)
	cmd.Dir = tempDir

	// Set environment
	cmd.Env = os.Environ()
	for k, v := range env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}

	// Start launcher
	if err := cmd.Start(); err != nil {
		os.RemoveAll(tempDir)
		t.Fatalf("Failed to start launcher: %v", err)
	}

	proc := &LauncherProcess{
		Cmd:     cmd,
		Env:     env,
		TempDir: tempDir,
		owned:   owned,
	}

	// Cleanup on test completion
	t.Cleanup(func() {
		proc.Stop(t)
	})

	return proc
}

// Stop terminates the launcher process and cleans up
func (p *LauncherProcess) Stop(t *testing.T) {
	t.Helper()

	if p.Cmd != nil && p.Cmd.Process != nil {
		// Try graceful shutdown first
		p.Cmd.Process.Signal(os.Interrupt)
		time.Sleep(100 * time.Millisecond)

		// Force kill if still running
		if p.Cmd.ProcessState == nil || !p.Cmd.ProcessState.Exited() {
			p.Cmd.Process.Kill()
		}
		p.Cmd.Wait()
	}

	// Clean up temp directory
	if p.owned && p.TempDir != "" {
		os.RemoveAll(p.TempDir)
	}
}

// WaitForExit waits for the launcher to exit and returns exit code
func (p *LauncherProcess) WaitForExit(timeout time.Duration) (int, error) {
	done := make(chan error, 1)
	go func() {
		done <- p.Cmd.Wait()
	}()

	select {
	case err := <-done:
		if err != nil {
			if exitErr, ok := err.(*exec.ExitError); ok {
				return exitErr.ExitCode(), nil
			}
			return -1, err
		}
		return 0, nil
	case <-time.After(timeout):
		return -1, fmt.Errorf("timeout waiting for exit")
	}
}

// GetPID reads the PID file for a service
func GetPID(t *testing.T, tempDir, name string) (int, error) {
	t.Helper()

	pidFile := filepath.Join(tempDir, ".build/pids", name+".pid")
	data, err := os.ReadFile(pidFile)
	if err != nil {
		return 0, err
	}

	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return 0, err
	}

	return pid, nil
}

// IsProcessRunning checks if a process is still alive
func IsProcessRunning(pid int) bool {
	process, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	return process.Signal(os.Signal(nil)) == nil
}

// WaitForHealth polls an HTTP health endpoint
func WaitForHealth(t *testing.T, url string, timeout time.Duration) bool {
	t.Helper()

	client := &http.Client{Timeout: 100 * time.Millisecond}
	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		resp, err := client.Get(url)
		if err == nil && resp.StatusCode == 200 {
			resp.Body.Close()
			return true
		}
		if resp != nil {
			resp.Body.Close()
		}
		time.Sleep(50 * time.Millisecond)
	}

	return false
}

// FindFreePort finds an available TCP port
func FindFreePort(t *testing.T) string {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to find free port: %v", err)
	}
	defer ln.Close()

	_, port, _ := net.SplitHostPort(ln.Addr().String())
	return port
}

// BuildMock builds a mock binary from the fixtures directory
func BuildMock(t *testing.T, name string) string {
	t.Helper()

	sourceDir := filepath.Join("/home/gavin/work/sb/work/raw/launcher/test/fixtures", name)
	outputPath := filepath.Join(t.TempDir(), name)

	cmd := exec.Command("go", "build", "-o", outputPath, ".")
	cmd.Dir = sourceDir
	// Fixture modules are standalone; disable parent go.work so build resolves
	// within the fixture's own go.mod.
	cmd.Env = append(os.Environ(), "GOWORK=off")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("Failed to build mock %s: %v\n%s", name, err, output)
	}

	return outputPath
}

// SetupPrebuiltEnvironment creates .build/bin and manifest.json for prebuilt tests
func SetupPrebuiltEnvironment(t *testing.T, tempDir string, binaries map[string]string) {
	t.Helper()

	// Create directories
	binDir := filepath.Join(tempDir, ".build/bin")
	pidDir := filepath.Join(tempDir, ".build/pids")
	logDir := filepath.Join(tempDir, ".build/logs")
	dataDir := filepath.Join(tempDir, ".build/data")

	for _, dir := range []string{binDir, pidDir, logDir, dataDir} {
		if err := os.MkdirAll(dir, 0755); err != nil {
			t.Fatalf("Failed to create dir %s: %v", dir, err)
		}
	}

	// Copy binaries
	for destName, srcPath := range binaries {
		destPath := filepath.Join(binDir, destName)
		input, err := os.ReadFile(srcPath)
		if err != nil {
			t.Fatalf("Failed to read binary %s: %v", srcPath, err)
		}
		if err := os.WriteFile(destPath, input, 0755); err != nil {
			t.Fatalf("Failed to write binary %s: %v", destPath, err)
		}
	}

	// Create manifest.json
	manifestPath := filepath.Join(tempDir, "manifest.json")
	manifest := []map[string]string{}
	for name := range binaries {
		manifest = append(manifest, map[string]string{
			"id":     strings.TrimPrefix(name, "plugin-"),
			"binary": name,
		})
	}

	// Write manifest (simple JSON construction)
	var sb strings.Builder
	sb.WriteString("[\n")
	first := true
	for _, item := range manifest {
		if !first {
			sb.WriteString(",\n")
		}
		first = false
		sb.WriteString(fmt.Sprintf(`  {"id": "%s", "binary": "%s"}`, item["id"], item["binary"]))
	}
	sb.WriteString("\n]\n")

	if err := os.WriteFile(manifestPath, []byte(sb.String()), 0644); err != nil {
		t.Fatalf("Failed to write manifest: %v", err)
	}
}

// WaitForFile waits for a file to exist
func WaitForFile(t *testing.T, path string, timeout time.Duration) bool {
	t.Helper()

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return false
}
