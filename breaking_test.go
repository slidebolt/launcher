//go:build weaknesses

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/slidebolt/launcher/test/helpers"
)

// ============================================
// BREAKING TESTS - Expose System Weaknesses
// These tests are designed to fail and expose
// edge cases and race conditions in the system
// ============================================

// TestRapidStartStop exposes race condition in lock acquisition
// WEAKNESS: Lock file cleanup may race with rapid restart
func TestRapidStartStop(t *testing.T) {
	mockGateway := testhelpers.BuildMock(t, "mock_gateway")

	for i := 0; i < 5; i++ {
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

		proc := testhelpers.StartLauncher(t, env, "up")
		time.Sleep(200 * time.Millisecond)
		proc.Stop(t)

		// Immediately try to start again
		proc2 := testhelpers.StartLauncher(t, env, "up")
		time.Sleep(200 * time.Millisecond)

		// This may fail if lock file wasn't cleaned up properly
		if proc2.Cmd.ProcessState != nil && proc2.Cmd.ProcessState.Exited() {
			t.Errorf("Iteration %d: Second instance failed to start - possible lock file race", i)
		}

		proc2.Stop(t)
		time.Sleep(100 * time.Millisecond) // Brief pause between iterations
	}
}

// TestStaleLockFile exposes weakness in lock cleanup
// WEAKNESS: If launcher crashes, lock file may prevent restart
func TestStaleLockFile(t *testing.T) {
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

	// Create a stale lock file (simulating crash)
	lockFile := filepath.Join(tempDir, ".launcher.lock")
	if err := os.WriteFile(lockFile, []byte(""), 0644); err != nil {
		t.Fatalf("Failed to create stale lock file: %v", err)
	}

	// Try to start launcher
	proc := testhelpers.StartLauncher(t, env, "up")
	time.Sleep(500 * time.Millisecond)

	// Check if it started despite stale lock
	if proc.Cmd.ProcessState != nil && proc.Cmd.ProcessState.Exited() {
		t.Error("Launcher should handle stale lock files gracefully, but it failed")
	}

	proc.Stop(t)
}

// TestConcurrentStatusCommands exposes weakness in file-based state
// WEAKNESS: Race conditions when reading PID files during state changes
func TestConcurrentStatusCommands(t *testing.T) {
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

	proc := testhelpers.StartLauncher(t, env, "up")

	// Wait for startup
	time.Sleep(300 * time.Millisecond)

	// Spawn many concurrent status commands
	var wg sync.WaitGroup
	errors := make(chan error, 20)

	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			launcherBin := filepath.Join(proc.TempDir, "launcher")
			cmd := exec.Command(launcherBin, "status")
			cmd.Dir = tempDir
			output, err := cmd.CombinedOutput()
			if err != nil {
				errors <- fmt.Errorf("status command failed: %v\n%s", err, output)
			}
		}()
	}

	wg.Wait()
	close(errors)

	errCount := 0
	for err := range errors {
		t.Logf("Concurrent status error: %v", err)
		errCount++
	}

	if errCount > 0 {
		t.Errorf("Got %d errors from concurrent status commands - possible race condition", errCount)
	}

	proc.Stop(t)
}

// TestRapidPluginCrash exposes supervisor limit/bug
// WEAKNESS: Supervisor may not handle rapid successive crashes
func TestRapidPluginCrash(t *testing.T) {
	mockGateway := testhelpers.BuildMock(t, "mock_gateway")
	mockPlugin := testhelpers.BuildMock(t, "mock_plugin")

	tempDir := t.TempDir()
	env := map[string]string{
		"LAUNCHER_API_PORT":   testhelpers.FindFreePort(t),
		"LAUNCHER_NATS_PORT":  testhelpers.FindFreePort(t),
		"LAUNCHER_PREBUILT":   "true",
		"LAUNCHER_SKIP_NATS":  "true",
		"MOCK_PLUGIN_EXIT_MS": "50", // Very fast crash
	}

	binaries := map[string]string{
		"gateway":     mockGateway,
		"plugin-fast": mockPlugin,
	}
	testhelpers.SetupPrebuiltEnvironment(t, tempDir, binaries)

	proc := testhelpers.StartLauncher(t, env, "up")

	// Let it run for a bit with rapid restarts
	time.Sleep(2 * time.Second)

	// Check if supervisor is still working
	pluginPIDPath := filepath.Join(tempDir, ".build/pids/plugin-fast.pid")
	if !testhelpers.WaitForFile(t, pluginPIDPath, 1*time.Second) {
		t.Error("Supervisor may have stopped restarting plugin after rapid crashes")
	}

	// Count how many times it restarted (check log file size/entries)
	logFile := filepath.Join(tempDir, ".build/logs/plugin-fast.log")
	if content, err := os.ReadFile(logFile); err == nil {
		restartCount := strings.Count(string(content), "starting")
		if restartCount < 10 {
			t.Errorf("Plugin only restarted %d times in 2 seconds - supervisor may have failed", restartCount)
		}
	}

	proc.Stop(t)
}

// TestPartialStartupCleanup exposes cleanup weakness
// WEAKNESS: If NATS starts but gateway fails, cleanup may be incomplete
func TestPartialStartupCleanup(t *testing.T) {
	// Use failing gateway but let NATS start
	mockFailingGateway := testhelpers.BuildMock(t, "mock_failing_gateway")

	tempDir := t.TempDir()
	env := map[string]string{
		"LAUNCHER_API_PORT":  testhelpers.FindFreePort(t),
		"LAUNCHER_NATS_PORT": testhelpers.FindFreePort(t),
		"LAUNCHER_PREBUILT":  "true",
		// Don't skip NATS - let it start
	}

	binaries := map[string]string{
		"gateway": mockFailingGateway,
	}
	testhelpers.SetupPrebuiltEnvironment(t, tempDir, binaries)

	proc := testhelpers.StartLauncher(t, env, "up")

	// Wait for it to fail
	exitCode, _ := proc.WaitForExit(15 * time.Second)

	// Check that all PID files were cleaned up
	pidFiles, _ := filepath.Glob(filepath.Join(tempDir, ".build/pids/*.pid"))
	if len(pidFiles) > 0 {
		t.Errorf("Found %d stale PID files after failed startup - cleanup incomplete: %v", len(pidFiles), pidFiles)
	}

	// Check if NATS process was cleaned up
	// (This is hard to verify without knowing the PID, but we can check for nats.log)
	natsLog := filepath.Join(tempDir, ".build/logs/nats.log")
	if _, err := os.Stat(natsLog); err == nil {
		// NATS was started - verify it's not still running would require checking /proc
		t.Log("NATS log exists - may indicate NATS was started but not cleaned up")
	}

	if exitCode == 0 {
		t.Error("Should have failed with bad gateway, but got success")
	}
}

// TestPIDReuse exposes weakness in PID-based tracking
// WEAKNESS: PID file may reference wrong process after restart
func TestPIDReuse(t *testing.T) {
	mockGateway := testhelpers.BuildMock(t, "mock_gateway")
	mockPlugin := testhelpers.BuildMock(t, "mock_plugin")

	tempDir := t.TempDir()
	env := map[string]string{
		"LAUNCHER_API_PORT":   testhelpers.FindFreePort(t),
		"LAUNCHER_NATS_PORT":  testhelpers.FindFreePort(t),
		"LAUNCHER_PREBUILT":   "true",
		"LAUNCHER_SKIP_NATS":  "true",
		"MOCK_PLUGIN_EXIT_MS": "1000",
	}

	binaries := map[string]string{
		"gateway":     mockGateway,
		"plugin-test": mockPlugin,
	}
	testhelpers.SetupPrebuiltEnvironment(t, tempDir, binaries)

	proc := testhelpers.StartLauncher(t, env, "up")
	time.Sleep(500 * time.Millisecond)

	// Get initial PID
	initialPID, err := testhelpers.GetPID(t, tempDir, "plugin-test")
	if err != nil {
		t.Fatalf("Failed to get initial PID: %v", err)
	}

	// Wait for crash and restart
	time.Sleep(1500 * time.Millisecond)

	// Get new PID
	newPID, err := testhelpers.GetPID(t, tempDir, "plugin-test")
	if err != nil {
		t.Fatalf("Failed to get new PID: %v", err)
	}
	_ = newPID // We document the risk below but don't need to use it

	// Verify old PID is gone
	if testhelpers.IsProcessRunning(initialPID) {
		t.Error("Old process should not be running")
	}

	// The weakness: if PID was reused by another process, we'd kill wrong thing
	// This test documents that risk

	proc.Stop(t)
}

// TestLongPluginName exposes filename/path handling weakness
// WEAKNESS: Very long names may cause issues with PID/log files
func TestLongPluginName(t *testing.T) {
	mockGateway := testhelpers.BuildMock(t, "mock_gateway")
	mockPlugin := testhelpers.BuildMock(t, "mock_plugin")

	tempDir := t.TempDir()
	env := map[string]string{
		"LAUNCHER_API_PORT":  testhelpers.FindFreePort(t),
		"LAUNCHER_NATS_PORT": testhelpers.FindFreePort(t),
		"LAUNCHER_PREBUILT":  "true",
		"LAUNCHER_SKIP_NATS": "true",
	}

	// Create a plugin with a very long name (100 chars)
	longName := "plugin-" + strings.Repeat("a", 93)
	binaries := map[string]string{
		"gateway": mockGateway,
		longName:  mockPlugin,
	}
	testhelpers.SetupPrebuiltEnvironment(t, tempDir, binaries)

	proc := testhelpers.StartLauncher(t, env, "up")
	time.Sleep(500 * time.Millisecond)

	// Check if it handled the long name
	pidPath := filepath.Join(tempDir, ".build/pids", longName+".pid")
	logPath := filepath.Join(tempDir, ".build/logs", longName+".log")

	pidExists := testhelpers.WaitForFile(t, pidPath, 2*time.Second)
	logExists := testhelpers.WaitForFile(t, logPath, 2*time.Second)

	if !pidExists {
		t.Error("Failed to create PID file for long plugin name")
	}
	if !logExists {
		t.Error("Failed to create log file for long plugin name")
	}

	proc.Stop(t)
}

// TestSpecialCharactersInName exposes filename sanitization weakness
// WEAKNESS: Special characters in names may break file operations
func TestSpecialCharactersInName(t *testing.T) {
	mockGateway := testhelpers.BuildMock(t, "mock_gateway")
	mockPlugin := testhelpers.BuildMock(t, "mock_plugin")

	tempDir := t.TempDir()
	env := map[string]string{
		"LAUNCHER_API_PORT":  testhelpers.FindFreePort(t),
		"LAUNCHER_NATS_PORT": testhelpers.FindFreePort(t),
		"LAUNCHER_PREBUILT":  "true",
		"LAUNCHER_SKIP_NATS": "true",
	}

	// Names with special characters
	specialNames := []string{
		"plugin-test.v1.0",
		"plugin_test-1",
		"plugin.with.dots",
	}

	binaries := map[string]string{
		"gateway": mockGateway,
	}
	for _, name := range specialNames {
		binaries[name] = mockPlugin
	}

	testhelpers.SetupPrebuiltEnvironment(t, tempDir, binaries)

	proc := testhelpers.StartLauncher(t, env, "up")
	time.Sleep(800 * time.Millisecond)

	// Check all plugins started
	for _, name := range specialNames {
		pidPath := filepath.Join(tempDir, ".build/pids", name+".pid")
		if !testhelpers.WaitForFile(t, pidPath, 2*time.Second) {
			t.Errorf("Plugin %s with special characters failed to start", name)
		}
	}

	proc.Stop(t)
}

// TestMissingPluginEnvFile exposes error handling weakness
// WEAKNESS: May crash if plugin env file referenced but missing
func TestMissingPluginEnvFile(t *testing.T) {
	mockGateway := testhelpers.BuildMock(t, "mock_gateway")
	mockPlugin := testhelpers.BuildMock(t, "mock_plugin")

	tempDir := t.TempDir()
	env := map[string]string{
		"LAUNCHER_API_PORT":           testhelpers.FindFreePort(t),
		"LAUNCHER_NATS_PORT":          testhelpers.FindFreePort(t),
		"LAUNCHER_PREBUILT":           "true",
		"LAUNCHER_SKIP_NATS":          "true",
		"LAUNCHER_PLUGIN_CONFIG_ROOT": filepath.Join(tempDir, "nonexistent", "config"),
	}

	binaries := map[string]string{
		"gateway":     mockGateway,
		"plugin-test": mockPlugin,
	}
	testhelpers.SetupPrebuiltEnvironment(t, tempDir, binaries)

	proc := testhelpers.StartLauncher(t, env, "up")
	time.Sleep(500 * time.Millisecond)

	// Should still work even if plugin config dir doesn't exist
	pluginPIDPath := filepath.Join(tempDir, ".build/pids/plugin-test.pid")
	if !testhelpers.WaitForFile(t, pluginPIDPath, 2*time.Second) {
		t.Error("Plugin should start even with missing env file directory")
	}

	proc.Stop(t)
}

// TestSignalDuringStartup exposes signal handling weakness
// WEAKNESS: Signals during startup may leave system in inconsistent state
func TestSignalDuringStartup(t *testing.T) {
	mockGateway := testhelpers.BuildMock(t, "mock_gateway")

	tempDir := t.TempDir()
	port := testhelpers.FindFreePort(t)
	env := map[string]string{
		"LAUNCHER_API_PORT":  port,
		"LAUNCHER_NATS_PORT": testhelpers.FindFreePort(t),
		"LAUNCHER_PREBUILT":  "true",
		"LAUNCHER_SKIP_NATS": "true",
		"MOCK_DELAY_MS":      "2000", // Slow gateway start
	}

	binaries := map[string]string{
		"gateway": mockGateway,
	}
	testhelpers.SetupPrebuiltEnvironment(t, tempDir, binaries)

	proc := testhelpers.StartLauncher(t, env, "up")

	// Send signal immediately (during startup delay)
	time.Sleep(500 * time.Millisecond)
	if proc.Cmd.Process != nil {
		proc.Cmd.Process.Signal(os.Interrupt)
	}

	// Wait for shutdown
	proc.WaitForExit(5 * time.Second)

	// Check for leftover files
	lockFile := filepath.Join(tempDir, ".launcher.lock")
	pidFile := filepath.Join(tempDir, ".launcher.pid")

	if _, err := os.Stat(lockFile); err == nil {
		t.Error("Lock file should be cleaned up after interrupt during startup")
	}
	if _, err := os.Stat(pidFile); err == nil {
		t.Error("PID file should be cleaned up after interrupt during startup")
	}
}

// TestManyPlugins exposes resource/scaling weakness
// WEAKNESS: System may fail with many plugins
func TestManyPlugins(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping many plugins test in short mode")
	}

	mockGateway := testhelpers.BuildMock(t, "mock_gateway")
	mockPlugin := testhelpers.BuildMock(t, "mock_plugin")

	tempDir := t.TempDir()
	env := map[string]string{
		"LAUNCHER_API_PORT":  testhelpers.FindFreePort(t),
		"LAUNCHER_NATS_PORT": testhelpers.FindFreePort(t),
		"LAUNCHER_PREBUILT":  "true",
		"LAUNCHER_SKIP_NATS": "true",
	}

	// Create 20 plugins
	binaries := map[string]string{
		"gateway": mockGateway,
	}
	for i := 0; i < 20; i++ {
		binaries[fmt.Sprintf("plugin-%d", i)] = mockPlugin
	}

	testhelpers.SetupPrebuiltEnvironment(t, tempDir, binaries)

	start := time.Now()
	proc := testhelpers.StartLauncher(t, env, "up")

	// Wait for all to start
	time.Sleep(2 * time.Second)

	elapsed := time.Since(start)

	// Count how many started
	started := 0
	for i := 0; i < 20; i++ {
		pidPath := filepath.Join(tempDir, ".build/pids", fmt.Sprintf("plugin-%d.pid", i))
		if _, err := os.Stat(pidPath); err == nil {
			started++
		}
	}

	if started < 20 {
		t.Errorf("Only %d/20 plugins started - scaling issue", started)
	}

	t.Logf("Started %d plugins in %v", started, elapsed)

	proc.Stop(t)
}

// TestCorruptedPIDFile exposes error handling weakness
// WEAKNESS: Corrupted PID file may cause unexpected behavior
func TestCorruptedPIDFile(t *testing.T) {
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

	// Create corrupted PID file
	pidDir := filepath.Join(tempDir, ".build/pids")
	os.MkdirAll(pidDir, 0755)
	os.WriteFile(filepath.Join(pidDir, "gateway.pid"), []byte("not-a-number"), 0644)

	proc := testhelpers.StartLauncher(t, env, "up")
	time.Sleep(500 * time.Millisecond)

	// Check if it handled the corrupted file
	pidPath := filepath.Join(pidDir, "gateway.pid")
	content, _ := os.ReadFile(pidPath)
	newPID := strings.TrimSpace(string(content))

	// Should have overwritten with valid PID
	if _, err := strconv.Atoi(newPID); err != nil {
		t.Errorf("PID file not corrected after corrupted content: %s", newPID)
	}
	_ = newPID // Acknowledge we use it

	proc.Stop(t)
}

// TestEmptyEnvironmentVariables exposes edge case handling
// WEAKNESS: Empty strings may be treated differently than unset
func TestEmptyEnvironmentVariables(t *testing.T) {
	mockGateway := testhelpers.BuildMock(t, "mock_gateway")

	tempDir := t.TempDir()
	env := map[string]string{
		"LAUNCHER_API_PORT":  "", // Empty - should use default
		"LAUNCHER_NATS_PORT": "", // Empty - should use default
		"LAUNCHER_PREBUILT":  "true",
		"LAUNCHER_SKIP_NATS": "true",
	}

	binaries := map[string]string{
		"gateway": mockGateway,
	}
	testhelpers.SetupPrebuiltEnvironment(t, tempDir, binaries)

	proc := testhelpers.StartLauncher(t, env, "up")
	time.Sleep(500 * time.Millisecond)

	// Should use default port (8082)
	// Check if it started successfully
	if proc.Cmd.ProcessState != nil && proc.Cmd.ProcessState.Exited() {
		t.Error("Launcher should use defaults for empty env vars, but it failed")
	}

	proc.Stop(t)
}

// TestBinaryNotExecutable exposes permission handling weakness
// WEAKNESS: May not handle permission errors gracefully
func TestBinaryNotExecutable(t *testing.T) {
	mockGateway := testhelpers.BuildMock(t, "mock_gateway")

	tempDir := t.TempDir()
	env := map[string]string{
		"LAUNCHER_API_PORT":  testhelpers.FindFreePort(t),
		"LAUNCHER_NATS_PORT": testhelpers.FindFreePort(t),
		"LAUNCHER_PREBUILT":  "true",
		"LAUNCHER_SKIP_NATS": "true",
	}

	// Setup prebuilt with non-executable binary
	binDir := filepath.Join(tempDir, ".build/bin")
	os.MkdirAll(binDir, 0755)

	// Copy gateway but make it non-executable
	srcData, _ := os.ReadFile(mockGateway)
	destPath := filepath.Join(binDir, "gateway")
	os.WriteFile(destPath, srcData, 0644) // No execute permission
	os.Chmod(destPath, 0644)

	manifest := `[{"id": "gateway", "binary": "gateway"}]`
	os.WriteFile(filepath.Join(tempDir, "manifest.json"), []byte(manifest), 0644)

	proc := testhelpers.StartLauncher(t, env, "up")

	// Should fail to start non-executable binary
	exitCode, _ := proc.WaitForExit(5 * time.Second)

	if exitCode == 0 {
		t.Error("Should fail when binary is not executable")
	}
}

// TestStopDuringPluginRestart exposes timing weakness
// WEAKNESS: Stopping during plugin restart may orphan process
func TestStopDuringPluginRestart(t *testing.T) {
	mockGateway := testhelpers.BuildMock(t, "mock_gateway")
	mockPlugin := testhelpers.BuildMock(t, "mock_plugin")

	tempDir := t.TempDir()
	env := map[string]string{
		"LAUNCHER_API_PORT":   testhelpers.FindFreePort(t),
		"LAUNCHER_NATS_PORT":  testhelpers.FindFreePort(t),
		"LAUNCHER_PREBUILT":   "true",
		"LAUNCHER_SKIP_NATS":  "true",
		"MOCK_PLUGIN_EXIT_MS": "250", // Crash every 250ms
	}

	binaries := map[string]string{
		"gateway":     mockGateway,
		"plugin-test": mockPlugin,
	}
	testhelpers.SetupPrebuiltEnvironment(t, tempDir, binaries)

	proc := testhelpers.StartLauncher(t, env, "up")
	time.Sleep(500 * time.Millisecond) // Let it crash a few times

	// Stop during the 200ms restart delay
	time.Sleep(50 * time.Millisecond)
	proc.Stop(t)

	// Wait a bit
	time.Sleep(500 * time.Millisecond)

	// Check for any remaining processes
	pidPath := filepath.Join(tempDir, ".build/pids/plugin-test.pid")
	if content, err := os.ReadFile(pidPath); err == nil {
		pid, _ := strconv.Atoi(strings.TrimSpace(string(content)))
		if testhelpers.IsProcessRunning(pid) {
			t.Error("Plugin process orphaned after stop during restart")
		}
	}
}

// TestStatusWithNoServices exposes error message quality
// WEAKNESS: Status command may fail confusingly when no services
func TestStatusWithNoServices(t *testing.T) {
	tempDir := t.TempDir()

	// Setup directories but no binaries running
	os.MkdirAll(filepath.Join(tempDir, ".build/pids"), 0755)
	os.MkdirAll(filepath.Join(tempDir, ".build/logs"), 0755)

	// Build launcher
	launcherBin := filepath.Join(tempDir, "launcher")
	buildCmd := exec.Command("go", "build", "-o", launcherBin, ".")
	buildCmd.Dir = "/home/gavin/work/sb/work/raw/launcher"
	buildCmd.CombinedOutput()

	// Run status with no services
	cmd := exec.Command(launcherBin, "status")
	cmd.Dir = tempDir
	output, err := cmd.CombinedOutput()

	outputStr := string(output)
	t.Logf("Status output with no services: %s", outputStr)

	// Should handle gracefully
	if err != nil && !strings.Contains(outputStr, "No services") {
		t.Errorf("Status should handle no services gracefully, got: %s", outputStr)
	}
}

// TestInvalidManifest exposes JSON parsing weakness
// WEAKNESS: Invalid manifest may cause panic or undefined behavior
func TestInvalidManifest(t *testing.T) {
	tempDir := t.TempDir()
	env := map[string]string{
		"LAUNCHER_API_PORT":  testhelpers.FindFreePort(t),
		"LAUNCHER_NATS_PORT": testhelpers.FindFreePort(t),
		"LAUNCHER_PREBUILT":  "true",
		"LAUNCHER_SKIP_NATS": "true",
	}

	// Setup with invalid JSON
	binDir := filepath.Join(tempDir, ".build/bin")
	os.MkdirAll(binDir, 0755)
	os.WriteFile(filepath.Join(tempDir, "manifest.json"), []byte("not valid json"), 0644)

	proc := testhelpers.StartLauncher(t, env, "up")

	exitCode, _ := proc.WaitForExit(5 * time.Second)

	if exitCode == 0 {
		t.Error("Should fail with invalid manifest")
	}
}
