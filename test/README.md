# Launcher Integration Tests

This directory contains comprehensive integration tests for the launcher application.

## Test Structure

```
test/
├── fixtures/           # Mock binaries for testing
│   ├── mock_gateway/        # HTTP gateway that responds to health checks
│   ├── mock_plugin/         # Plugin that logs env vars
│   ├── mock_failing_gateway/ # Gateway that always fails health checks
│   └── stubborn_service/    # Service that ignores SIGTERM
├── helpers/            # Test utilities
│   └── helpers.go      # LauncherProcess, BuildMock, etc.
└── README.md           # This file
```

## Running Tests

### Run All Tests
```bash
cd /home/gavin/work/sb/work/raw/launcher
go test -v ./...
```

### Run Specific Test
```bash
go test -v -run TestSingleInstanceLock
```

### Run Critical Tests Only (Fast)
```bash
go test -v -run "TestSingleInstanceLock|TestFullLifecycle|TestPluginCrashRecovery|TestGatewayHealthTimeout|TestGatewayHealthSlowStart"
```

### Run with Timeout
```bash
go test -v -timeout 5m ./...
```

## Test Categories

### Critical Priority (Must Pass)

1. **TestSingleInstanceLock** - Verifies only one launcher can run at a time
2. **TestFullLifecycle** - Complete start/stop cycle verification
3. **TestPluginCrashRecovery** - Supervisor restarts crashed plugins
4. **TestGatewayHealthTimeout** - Launcher exits when gateway unhealthy
5. **TestGatewayHealthSlowStart** - Waits for slow gateway

### High Priority

6. **TestPortAlreadyInUse** - Graceful failure on port conflict
7. **TestRandomPortAssignment** - Port 0 finds available port
8. **TestEnvVarResolution** - Environment variables resolved correctly
9. **TestEnvVarFallbacks** - Default values work correctly
10. **TestPrebuiltModeValidation** - Uses prebuilt binaries correctly
11. **TestPrebuiltModeMissingBinary** - Fails when binary missing
12. **TestGracefulShutdownTimeout** - Force kill after graceful timeout

### Medium Priority

13. **TestPluginDiscovery** - Correct filtering of plugin directories
14. **TestEmptyPluginDirectory** - Works with no plugins
15. **TestStatusCommand** - Status displays running services
16. **TestLogFileCreation** - Log files created for services

## Test Design Principles

1. **Integration over Unit** - These are integration tests that verify end-to-end workflows
2. **Isolation** - Each test gets its own temp directory
3. **Mock Services** - Real processes are spawned for realistic testing
4. **Timeout Protection** - All blocking operations have timeouts
5. **Cleanup** - t.Cleanup ensures resources are freed even on failure

## Adding New Tests

1. Add mock binary to `fixtures/` if needed
2. Use `testhelpers.StartLauncher()` to spawn launcher
3. Use `testhelpers.BuildMock()` to compile fixtures
4. Use `testhelpers.SetupPrebuiltEnvironment()` for prebuilt mode tests
5. Always call `proc.Stop(t)` or rely on t.Cleanup
6. Use `testhelpers.WaitForFile()` for polling file existence
7. Use `testhelpers.WaitForHealth()` for polling HTTP endpoints

## Known Limitations

- Tests require Go toolchain to build launcher and mocks
- Tests use actual ports (though isolated per test)
- Tests spawn real processes (not parallelizable without port coordination)
- Some tests may be flaky on heavily loaded systems
