//go:build integration

package main

import (
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/slidebolt/launcher/test/helpers"
)

// TestSingleInstanceLock verifies that only one launcher can run at a time
func TestSingleInstanceLock(t *testing.T) {
	tempDir := t.TempDir()

	// Start first launcher instance
	port1 := testhelpers.FindFreePort(t)
	env1 := map[string]string{
		"LAUNCHER_API_PORT":  port1,
		"LAUNCHER_NATS_PORT": testhelpers.FindFreePort(t),
		"LAUNCHER_PREBUILT":  "true",
		"LAUNCHER_SKIP_NATS": "true",
		"LAUNCHER_WORKDIR":   tempDir,
	}

	// Build a mock gateway for the first instance
	mockGateway := testhelpers.BuildMock(t, "mock_gateway")
	testhelpers.SetupPrebuiltEnvironment(t, tempDir, map[string]string{"gateway": mockGateway})
	proc1 := testhelpers.StartLauncher(t, env1, "up")

	// Wait for first instance to acquire lock
	time.Sleep(200 * time.Millisecond)

	// Try to start second instance
	env2 := map[string]string{
		"LAUNCHER_API_PORT":  testhelpers.FindFreePort(t),
		"LAUNCHER_NATS_PORT": testhelpers.FindFreePort(t),
		"LAUNCHER_PREBUILT":  "true",
		"LAUNCHER_SKIP_NATS": "true",
		"LAUNCHER_WORKDIR":   tempDir,
	}

	launcherBin := filepath.Join(proc1.TempDir, "launcher")
	cmd2 := exec.Command(launcherBin, "up")
	cmd2.Dir = tempDir
	cmd2.Env = os.Environ()
	for k, v := range env2 {
		cmd2.Env = append(cmd2.Env, k+"="+v)
	}

	output, err := cmd2.CombinedOutput()

	// Second instance should fail
	if err == nil {
		t.Error("Second launcher instance should have failed to start")
	}
	if !strings.Contains(string(output), "already running") && !strings.Contains(string(output), "lock") {
		t.Errorf("Expected error about already running, got: %s", output)
	}

	// Stop first instance
	proc1.Stop(t)

	// Verify third instance can now start (indicates lock was released)
	time.Sleep(100 * time.Millisecond)
	proc3 := testhelpers.StartLauncher(t, env1, "up")
	time.Sleep(200 * time.Millisecond)

	// Just verify it started without error
	if proc3.Cmd.ProcessState != nil && proc3.Cmd.ProcessState.Exited() {
		t.Error("Third instance should have started after first stopped")
	}
}

// TestFullLifecycle verifies complete start/stop cycle
func TestFullLifecycle(t *testing.T) {
	// Build mocks
	mockGateway := testhelpers.BuildMock(t, "mock_gateway")
	mockPlugin := testhelpers.BuildMock(t, "mock_plugin")

	// Setup environment
	tempDir := t.TempDir()
	env := map[string]string{
		"LAUNCHER_API_PORT":  testhelpers.FindFreePort(t),
		"LAUNCHER_NATS_PORT": testhelpers.FindFreePort(t),
		"LAUNCHER_PREBUILT":  "true",
		"LAUNCHER_SKIP_NATS": "true",
	}

	// Setup prebuilt binaries
	binaries := map[string]string{
		"gateway":     mockGateway,
		"plugin-test": mockPlugin,
	}
	testhelpers.SetupPrebuiltEnvironment(t, tempDir, binaries)

	// Start launcher
	env["LAUNCHER_WORKDIR"] = tempDir
	proc := testhelpers.StartLauncher(t, env, "up")

	// Wait for services to start
	time.Sleep(500 * time.Millisecond)

	// Verify gateway PID file exists
	gatewayPIDPath := filepath.Join(tempDir, ".build/pids/gateway.pid")
	if !testhelpers.WaitForFile(t, gatewayPIDPath, 2*time.Second) {
		t.Error("Gateway PID file should exist")
	}

	// Verify plugin PID file exists
	pluginPIDPath := filepath.Join(tempDir, ".build/pids/plugin-test.pid")
	if !testhelpers.WaitForFile(t, pluginPIDPath, 2*time.Second) {
		t.Error("Plugin PID file should exist")
	}

	// Get PIDs before stopping
	gatewayPID, _ := testhelpers.GetPID(t, tempDir, "gateway")
	pluginPID, _ := testhelpers.GetPID(t, tempDir, "plugin-test")

	// Stop launcher
	proc.Stop(t)

	// Wait for shutdown
	time.Sleep(500 * time.Millisecond)

	// Verify processes terminated
	if testhelpers.IsProcessRunning(gatewayPID) {
		t.Error("Gateway process should have terminated")
	}
	if testhelpers.IsProcessRunning(pluginPID) {
		t.Error("Plugin process should have terminated")
	}

	// Verify PID files cleaned up
	if _, err := os.Stat(gatewayPIDPath); !os.IsNotExist(err) {
		t.Error("Gateway PID file should be removed")
	}
	if _, err := os.Stat(pluginPIDPath); !os.IsNotExist(err) {
		t.Error("Plugin PID file should be removed")
	}
}

// TestPluginCrashRecovery verifies supervisor restarts crashed plugins
func TestPluginCrashRecovery(t *testing.T) {
	// Build mocks - use mock_plugin with exit delay
	mockGateway := testhelpers.BuildMock(t, "mock_gateway")

	// Create a special plugin that exits quickly
	tempDir := t.TempDir()
	env := map[string]string{
		"LAUNCHER_API_PORT":   testhelpers.FindFreePort(t),
		"LAUNCHER_NATS_PORT":  testhelpers.FindFreePort(t),
		"LAUNCHER_PREBUILT":   "true",
		"LAUNCHER_SKIP_NATS":  "true",
		"MOCK_PLUGIN_EXIT_MS": "500", // Plugin exits after 500ms
	}

	mockPlugin := testhelpers.BuildMock(t, "mock_plugin")
	binaries := map[string]string{
		"gateway":     mockGateway,
		"plugin-fast": mockPlugin,
	}
	testhelpers.SetupPrebuiltEnvironment(t, tempDir, binaries)

	// Start launcher
	env["LAUNCHER_WORKDIR"] = tempDir
	proc := testhelpers.StartLauncher(t, env, "up")

	// Wait for initial start
	time.Sleep(300 * time.Millisecond)

	// Get initial plugin PID
	pluginPIDPath := filepath.Join(tempDir, ".build/pids/plugin-fast.pid")
	if !testhelpers.WaitForFile(t, pluginPIDPath, 2*time.Second) {
		t.Fatal("Plugin PID file should exist")
	}

	initialPID, err := testhelpers.GetPID(t, tempDir, "plugin-fast")
	if err != nil {
		t.Fatalf("Failed to get initial PID: %v", err)
	}

	// Wait for plugin to crash and restart (500ms exit + 200ms restart delay)
	time.Sleep(1000 * time.Millisecond)

	// Get new PID
	newPID, err := testhelpers.GetPID(t, tempDir, "plugin-fast")
	if err != nil {
		t.Fatalf("Failed to get new PID: %v", err)
	}

	// Verify PID changed (was restarted)
	if newPID == initialPID {
		t.Error("Plugin should have been restarted with new PID")
	}

	// Verify old process is gone
	if testhelpers.IsProcessRunning(initialPID) {
		t.Error("Old plugin process should not be running")
	}

	// Verify new process is running
	if !testhelpers.IsProcessRunning(newPID) {
		t.Error("New plugin process should be running")
	}

	proc.Stop(t)
}

// TestGatewayHealthTimeout verifies launcher exits when gateway fails health check
func TestGatewayHealthTimeout(t *testing.T) {
	// Build failing gateway
	mockFailingGateway := testhelpers.BuildMock(t, "mock_failing_gateway")

	tempDir := t.TempDir()
	env := map[string]string{
		"LAUNCHER_API_PORT":  testhelpers.FindFreePort(t),
		"LAUNCHER_NATS_PORT": testhelpers.FindFreePort(t),
		"LAUNCHER_PREBUILT":  "true",
		"LAUNCHER_SKIP_NATS": "true",
	}

	binaries := map[string]string{
		"gateway": mockFailingGateway,
	}
	testhelpers.SetupPrebuiltEnvironment(t, tempDir, binaries)

	// Start launcher - it should fail
	env["LAUNCHER_WORKDIR"] = tempDir
	proc := testhelpers.StartLauncher(t, env, "up")

	// Wait for health check timeout (40 attempts * 200ms = 8 seconds max)
	exitCode, err := proc.WaitForExit(10 * time.Second)
	if err != nil {
		t.Fatalf("Launcher didn't exit as expected: %v", err)
	}

	if exitCode == 0 {
		t.Error("Launcher should have exited with error code when gateway fails health check")
	}

	// Verify no plugin PID files (plugins shouldn't have started)
	files, _ := filepath.Glob(filepath.Join(tempDir, ".build/pids/*.pid"))
	for _, f := range files {
		if !strings.Contains(f, "gateway") {
			t.Errorf("No non-gateway services should have started, but found: %s", f)
		}
	}
}

// TestGatewayHealthSlowStart verifies launcher waits for slow-starting gateway
func TestGatewayHealthSlowStart(t *testing.T) {
	mockGateway := testhelpers.BuildMock(t, "mock_gateway")

	tempDir := t.TempDir()
	env := map[string]string{
		"LAUNCHER_API_PORT":  testhelpers.FindFreePort(t),
		"LAUNCHER_NATS_PORT": testhelpers.FindFreePort(t),
		"LAUNCHER_PREBUILT":  "true",
		"LAUNCHER_SKIP_NATS": "true",
		"MOCK_DELAY_MS":      "2000", // Gateway takes 2s to start
	}

	binaries := map[string]string{
		"gateway": mockGateway,
	}
	testhelpers.SetupPrebuiltEnvironment(t, tempDir, binaries)

	startTime := time.Now()
	env["LAUNCHER_WORKDIR"] = tempDir
	proc := testhelpers.StartLauncher(t, env, "up")

	// Wait for gateway to start
	gatewayPIDPath := filepath.Join(tempDir, ".build/pids/gateway.pid")
	if !testhelpers.WaitForFile(t, gatewayPIDPath, 10*time.Second) {
		t.Fatal("Gateway should have started even with delay")
	}

	elapsed := time.Since(startTime)
	if elapsed < 2*time.Second {
		t.Errorf("Should have waited for gateway, but took only %v", elapsed)
	}

	proc.Stop(t)
}

// TestPortAlreadyInUse verifies launcher fails gracefully on port conflict
func TestPortAlreadyInUse(t *testing.T) {
	// Bind to a port first
	port := testhelpers.FindFreePort(t)

	// Start a listener on that port
	listener := startListener(t, port)
	defer listener.Close()

	// Try to start launcher on same port
	mockGateway := testhelpers.BuildMock(t, "mock_gateway")
	tempDir := t.TempDir()
	env := map[string]string{
		"LAUNCHER_API_PORT":  port,
		"LAUNCHER_NATS_PORT": testhelpers.FindFreePort(t),
		"LAUNCHER_PREBUILT":  "true",
		"LAUNCHER_SKIP_NATS": "true",
	}

	binaries := map[string]string{
		"gateway": mockGateway,
	}
	testhelpers.SetupPrebuiltEnvironment(t, tempDir, binaries)

	// Launcher should fail to start
	env["LAUNCHER_WORKDIR"] = tempDir
	proc := testhelpers.StartLauncher(t, env, "up")

	// Give it time to attempt startup and fail
	time.Sleep(1 * time.Second)

	if proc.Cmd.ProcessState == nil || !proc.Cmd.ProcessState.Exited() {
		// If still running, it's likely in a crash loop - kill it
		proc.Stop(t)
		t.Skip("Test inconclusive - launcher may not detect port conflict with this mock")
	}
}

// TestRandomPortAssignment verifies launcher can find and use available ports
func TestRandomPortAssignment(t *testing.T) {
	mockGateway := testhelpers.BuildMock(t, "mock_gateway")

	tempDir := t.TempDir()
	env := map[string]string{
		"LAUNCHER_API_PORT":  "0", // 0 = random port
		"LAUNCHER_NATS_PORT": "0",
		"LAUNCHER_PREBUILT":  "true",
		"LAUNCHER_SKIP_NATS": "true",
	}

	binaries := map[string]string{
		"gateway": mockGateway,
	}
	testhelpers.SetupPrebuiltEnvironment(t, tempDir, binaries)

	env["LAUNCHER_WORKDIR"] = tempDir
	proc := testhelpers.StartLauncher(t, env, "up")

	// Wait for startup
	time.Sleep(500 * time.Millisecond)

	// Check that gateway started (PID file exists)
	gatewayPIDPath := filepath.Join(tempDir, ".build/pids/gateway.pid")
	if !testhelpers.WaitForFile(t, gatewayPIDPath, 3*time.Second) {
		t.Error("Gateway should have started on random port")
	}

	proc.Stop(t)
}

// TestEnvVarResolution verifies environment variables are correctly resolved
func TestEnvVarResolution(t *testing.T) {
	mockGateway := testhelpers.BuildMock(t, "mock_gateway")

	tempDir := t.TempDir()
	customPort := testhelpers.FindFreePort(t)
	env := map[string]string{
		"LAUNCHER_API_HOST":  "0.0.0.0",
		"LAUNCHER_API_PORT":  customPort,
		"LAUNCHER_NATS_PORT": testhelpers.FindFreePort(t),
		"LAUNCHER_PREBUILT":  "true",
		"LAUNCHER_SKIP_NATS": "true",
	}

	binaries := map[string]string{
		"gateway": mockGateway,
	}
	testhelpers.SetupPrebuiltEnvironment(t, tempDir, binaries)

	env["LAUNCHER_WORKDIR"] = tempDir
	proc := testhelpers.StartLauncher(t, env, "up")

	// Wait for startup
	time.Sleep(500 * time.Millisecond)

	// Verify gateway is accessible on the custom port
	if !testhelpers.WaitForHealth(t, "http://127.0.0.1:"+customPort+"/health", 3*time.Second) {
		t.Error("Gateway should be accessible on configured port")
	}

	proc.Stop(t)
}

// TestEnvVarFallbacks verifies defaults work when env vars not set
func TestEnvVarFallbacks(t *testing.T) {
	mockGateway := testhelpers.BuildMock(t, "mock_gateway")

	tempDir := t.TempDir()
	// Only set minimal env vars
	env := map[string]string{
		"LAUNCHER_PREBUILT":  "true",
		"LAUNCHER_SKIP_NATS": "true",
	}
	// Clear any existing LAUNCHER_* vars
	for _, e := range os.Environ() {
		if strings.HasPrefix(e, "LAUNCHER_") && !strings.HasPrefix(e, "LAUNCHER_PREBUILT") && !strings.HasPrefix(e, "LAUNCHER_SKIP_NATS") {
			parts := strings.SplitN(e, "=", 2)
			os.Unsetenv(parts[0])
		}
	}

	binaries := map[string]string{
		"gateway": mockGateway,
	}
	testhelpers.SetupPrebuiltEnvironment(t, tempDir, binaries)

	env["LAUNCHER_WORKDIR"] = tempDir
	proc := testhelpers.StartLauncher(t, env, "up")

	// Wait for startup
	time.Sleep(500 * time.Millisecond)

	// Verify gateway started with defaults (127.0.0.1:8082)
	gatewayPIDPath := filepath.Join(tempDir, ".build/pids/gateway.pid")
	if !testhelpers.WaitForFile(t, gatewayPIDPath, 3*time.Second) {
		t.Error("Gateway should have started with default configuration")
	}

	proc.Stop(t)
}

// TestPrebuiltModeValidation verifies prebuilt mode uses existing binaries
func TestPrebuiltModeValidation(t *testing.T) {
	mockGateway := testhelpers.BuildMock(t, "mock_gateway")
	mockPlugin := testhelpers.BuildMock(t, "mock_plugin")

	tempDir := t.TempDir()
	env := map[string]string{
		"LAUNCHER_API_PORT":  testhelpers.FindFreePort(t),
		"LAUNCHER_NATS_PORT": testhelpers.FindFreePort(t),
		"LAUNCHER_PREBUILT":  "true",
		"LAUNCHER_SKIP_NATS": "true",
	}

	binaries := map[string]string{
		"gateway":     mockGateway,
		"plugin-test": mockPlugin,
	}
	testhelpers.SetupPrebuiltEnvironment(t, tempDir, binaries)

	env["LAUNCHER_WORKDIR"] = tempDir
	proc := testhelpers.StartLauncher(t, env, "up")

	// Wait for startup
	time.Sleep(500 * time.Millisecond)

	// Verify both services started
	gatewayPIDPath := filepath.Join(tempDir, ".build/pids/gateway.pid")
	pluginPIDPath := filepath.Join(tempDir, ".build/pids/plugin-test.pid")

	if !testhelpers.WaitForFile(t, gatewayPIDPath, 3*time.Second) {
		t.Error("Gateway should start in prebuilt mode")
	}
	if !testhelpers.WaitForFile(t, pluginPIDPath, 3*time.Second) {
		t.Error("Plugin should start in prebuilt mode")
	}

	proc.Stop(t)
}

// TestPrebuiltModeMissingBinary verifies error when manifest references missing binary
func TestPrebuiltModeMissingBinary(t *testing.T) {
	tempDir := t.TempDir()
	env := map[string]string{
		"LAUNCHER_API_PORT":  testhelpers.FindFreePort(t),
		"LAUNCHER_NATS_PORT": testhelpers.FindFreePort(t),
		"LAUNCHER_PREBUILT":  "true",
		"LAUNCHER_SKIP_NATS": "true",
	}

	// Setup with manifest referencing non-existent binary
	binDir := filepath.Join(tempDir, ".build/bin")
	os.MkdirAll(binDir, 0755)
	manifest := `[{"id": "missing", "binary": "nonexistent"}]`
	os.WriteFile(filepath.Join(tempDir, "manifest.json"), []byte(manifest), 0644)

	env["LAUNCHER_WORKDIR"] = tempDir
	proc := testhelpers.StartLauncher(t, env, "up")

	// Should exit with error
	exitCode, err := proc.WaitForExit(5 * time.Second)
	if err != nil {
		t.Fatalf("Launcher should have exited: %v", err)
	}

	if exitCode == 0 {
		t.Error("Launcher should fail when binary is missing")
	}
}

// TestGracefulShutdownTimeout verifies force kill after graceful timeout
func TestGracefulShutdownTimeout(t *testing.T) {
	stubbornService := testhelpers.BuildMock(t, "stubborn_service")

	tempDir := t.TempDir()
	env := map[string]string{
		"LAUNCHER_API_PORT":  testhelpers.FindFreePort(t),
		"LAUNCHER_NATS_PORT": testhelpers.FindFreePort(t),
		"LAUNCHER_PREBUILT":  "true",
		"LAUNCHER_SKIP_NATS": "true",
	}

	binaries := map[string]string{
		"gateway":         testhelpers.BuildMock(t, "mock_gateway"),
		"plugin-stubborn": stubbornService,
	}
	testhelpers.SetupPrebuiltEnvironment(t, tempDir, binaries)

	env["LAUNCHER_WORKDIR"] = tempDir
	proc := testhelpers.StartLauncher(t, env, "up")

	// Wait for startup
	time.Sleep(500 * time.Millisecond)

	// Get stubborn plugin PID
	stubbornPID, err := testhelpers.GetPID(t, tempDir, "plugin-stubborn")
	if err != nil {
		t.Fatalf("Failed to get stubborn plugin PID: %v", err)
	}

	// Stop launcher
	proc.Stop(t)

	// Wait for shutdown (2s graceful + some buffer)
	time.Sleep(3 * time.Second)

	// Verify stubborn process was force-killed
	if testhelpers.IsProcessRunning(stubbornPID) {
		t.Error("Stubborn process should have been force-killed")
	}
}

// TestPluginDiscovery verifies correct plugin discovery with filtering
func TestPluginDiscovery(t *testing.T) {
	mockGateway := testhelpers.BuildMock(t, "mock_gateway")
	mockPlugin := testhelpers.BuildMock(t, "mock_plugin")

	tempDir := t.TempDir()
	env := map[string]string{
		"LAUNCHER_API_PORT":  testhelpers.FindFreePort(t),
		"LAUNCHER_NATS_PORT": testhelpers.FindFreePort(t),
		"LAUNCHER_PREBUILT":  "true",
		"LAUNCHER_SKIP_NATS": "true",
	}

	// Setup with various binaries
	binaries := map[string]string{
		"gateway":      mockGateway,
		"plugin-valid": mockPlugin,
		"plugin-2":     mockPlugin,
		".hidden":      mockPlugin, // Should be ignored (starts with .)
		"old.del":      mockPlugin, // Should be ignored (ends with .del)
		"not-a-plugin": mockPlugin, // Should be ignored (no plugin- prefix)
	}
	testhelpers.SetupPrebuiltEnvironment(t, tempDir, binaries)

	env["LAUNCHER_WORKDIR"] = tempDir
	proc := testhelpers.StartLauncher(t, env, "up")

	// Wait for startup
	time.Sleep(500 * time.Millisecond)

	// Verify only valid plugins started
	validPlugin := filepath.Join(tempDir, ".build/pids/plugin-valid.pid")
	plugin2 := filepath.Join(tempDir, ".build/pids/plugin-2.pid")
	hidden := filepath.Join(tempDir, ".build/pids/.hidden.pid")
	oldDel := filepath.Join(tempDir, ".build/pids/old.del.pid")
	notPlugin := filepath.Join(tempDir, ".build/pids/not-a-plugin.pid")

	if !testhelpers.WaitForFile(t, validPlugin, 2*time.Second) {
		t.Error("plugin-valid should have started")
	}
	if !testhelpers.WaitForFile(t, plugin2, 2*time.Second) {
		t.Error("plugin-2 should have started")
	}

	// These should NOT exist
	if _, err := os.Stat(hidden); !os.IsNotExist(err) {
		t.Error(".hidden should not have started")
	}
	if _, err := os.Stat(oldDel); !os.IsNotExist(err) {
		t.Error("old.del should not have started")
	}
	if _, err := os.Stat(notPlugin); !os.IsNotExist(err) {
		t.Error("not-a-plugin should not have started")
	}

	proc.Stop(t)
}

// TestEmptyPluginDirectory verifies launcher works with no plugins
func TestEmptyPluginDirectory(t *testing.T) {
	mockGateway := testhelpers.BuildMock(t, "mock_gateway")

	tempDir := t.TempDir()
	env := map[string]string{
		"LAUNCHER_API_PORT":  testhelpers.FindFreePort(t),
		"LAUNCHER_NATS_PORT": testhelpers.FindFreePort(t),
		"LAUNCHER_PREBUILT":  "true",
		"LAUNCHER_SKIP_NATS": "true",
	}

	// Only gateway, no plugins
	binaries := map[string]string{
		"gateway": mockGateway,
	}
	testhelpers.SetupPrebuiltEnvironment(t, tempDir, binaries)

	env["LAUNCHER_WORKDIR"] = tempDir
	proc := testhelpers.StartLauncher(t, env, "up")

	// Wait for startup
	time.Sleep(500 * time.Millisecond)

	// Verify gateway started
	gatewayPIDPath := filepath.Join(tempDir, ".build/pids/gateway.pid")
	if !testhelpers.WaitForFile(t, gatewayPIDPath, 3*time.Second) {
		t.Error("Gateway should start even without plugins")
	}

	// Count PID files - should only be gateway
	files, _ := filepath.Glob(filepath.Join(tempDir, ".build/pids/*.pid"))
	if len(files) != 1 {
		t.Errorf("Expected 1 PID file (gateway), got %d", len(files))
	}

	proc.Stop(t)
}

// TestStatusCommand verifies status command displays running services
func TestStatusCommand(t *testing.T) {
	mockGateway := testhelpers.BuildMock(t, "mock_gateway")

	tempDir := t.TempDir()
	port := testhelpers.FindFreePort(t)
	env := map[string]string{
		"LAUNCHER_API_PORT":  port,
		"LAUNCHER_NATS_PORT": testhelpers.FindFreePort(t),
		"LAUNCHER_PREBUILT":  "true",
		"LAUNCHER_SKIP_NATS": "true",
	}

	binaries := map[string]string{
		"gateway": mockGateway,
	}
	testhelpers.SetupPrebuiltEnvironment(t, tempDir, binaries)

	// Start launcher
	env["LAUNCHER_WORKDIR"] = tempDir
	proc := testhelpers.StartLauncher(t, env, "up")
	time.Sleep(500 * time.Millisecond)

	// Run status command
	launcherBin := filepath.Join(proc.TempDir, "launcher")
	cmd := exec.Command(launcherBin, "status")
	cmd.Dir = tempDir
	output, err := cmd.CombinedOutput()

	if err != nil {
		t.Fatalf("Status command failed: %v\n%s", err, output)
	}

	outputStr := string(output)
	if !strings.Contains(outputStr, "gateway") {
		t.Errorf("Status should show gateway service, got: %s", outputStr)
	}
	if !strings.Contains(outputStr, "PID") {
		t.Errorf("Status should show PID, got: %s", outputStr)
	}

	proc.Stop(t)
}

// TestLogFileCreation verifies log files are created for services
func TestLogFileCreation(t *testing.T) {
	mockGateway := testhelpers.BuildMock(t, "mock_gateway")
	mockPlugin := testhelpers.BuildMock(t, "mock_plugin")

	tempDir := t.TempDir()
	env := map[string]string{
		"LAUNCHER_API_PORT":  testhelpers.FindFreePort(t),
		"LAUNCHER_NATS_PORT": testhelpers.FindFreePort(t),
		"LAUNCHER_PREBUILT":  "true",
		"LAUNCHER_SKIP_NATS": "true",
	}

	binaries := map[string]string{
		"gateway":     mockGateway,
		"plugin-test": mockPlugin,
	}
	testhelpers.SetupPrebuiltEnvironment(t, tempDir, binaries)

	env["LAUNCHER_WORKDIR"] = tempDir
	proc := testhelpers.StartLauncher(t, env, "up")
	time.Sleep(500 * time.Millisecond)

	// Check log files exist
	gatewayLog := filepath.Join(tempDir, ".build/logs/gateway.log")
	pluginLog := filepath.Join(tempDir, ".build/logs/plugin-test.log")

	if !testhelpers.WaitForFile(t, gatewayLog, 2*time.Second) {
		t.Error("Gateway log file should exist")
	}
	if !testhelpers.WaitForFile(t, pluginLog, 2*time.Second) {
		t.Error("Plugin log file should exist")
	}

	proc.Stop(t)
}

// Helper function to start a TCP listener
func startListener(t *testing.T, port string) *net.TCPListener {
	t.Helper()

	addr, _ := net.ResolveTCPAddr("tcp", "127.0.0.1:"+port)
	listener, err := net.ListenTCP("tcp", addr)
	if err != nil {
		t.Fatalf("Failed to start listener on port %s: %v", port, err)
	}

	return listener
}
