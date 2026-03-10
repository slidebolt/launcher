# High-Value Test Recommendations for Launcher

## Overview

Given this is a process orchestrator that manages the entire Slidebolt ecosystem, the highest-value tests are **integration tests** that verify end-to-end workflows. Unit tests have limited value here since most logic is coordination/orchestration.

---

## Critical Priority Tests (Must Have)

### 1. Single Instance Enforcement
**Risk:** Multiple launchers running simultaneously → state corruption, port conflicts, data loss

**Test: `TestSingleInstanceLock`**
- Spawn launcher in background with `up` command
- Attempt to spawn second launcher instance
- Verify second instance exits with error code
- Verify error message mentions lock file
- Kill first launcher, verify lock released
- Verify third launcher can now start

**Value:** Prevents catastrophic state corruption.

---

### 2. Service Lifecycle - Full Start/Stop Cycle
**Risk:** Services don't start, crash without restart, or don't stop cleanly

**Test: `TestFullLifecycle`**
- Run `launcher up` with test plugins
- Verify NATS starts and responds on expected port
- Verify gateway binary starts and PID file created
- Verify all plugin binaries start and PID files created
- Send SIGTERM to launcher
- Verify all PIDs terminate (check `/proc/<pid>` doesn't exist)
- Verify PID files cleaned up
- Verify log files contain orderly shutdown messages

**Value:** Core functionality - if this fails, the tool is useless.

---

### 3. Plugin Crash Recovery (Supervision)
**Risk:** Plugins crash and aren't restarted → service degradation

**Test: `TestPluginCrashRecovery`**
- Start launcher with a test plugin
- Find plugin PID from PID file
- Kill plugin process with SIGKILL
- Verify plugin restarts within 1 second (check new PID in file)
- Verify log shows restart message
- Repeat 3 times to verify continuous recovery

**Value:** Core supervision feature - ensures high availability.

---

### 4. Gateway Health Check Failure
**Risk:** Plugins start before gateway is ready → connection failures, race conditions

**Test: `TestGatewayHealthTimeout`**
- Create a mock gateway binary that never responds to health checks
- Start launcher with this mock
- Verify launcher exits with error after timeout
- Verify plugins never start (no PID files)
- Verify NATS gets cleaned up on failure

**Test: `TestGatewayHealthSlowStart`**
- Create mock gateway that responds after 3 seconds
- Verify launcher waits and eventually proceeds
- Verify plugins start after gateway healthy

**Value:** Prevents race conditions and partial startup states.

---

### 5. Port Conflict Handling
**Risk:** Configured ports in use → startup failures, cryptic errors

**Test: `TestPortAlreadyInUse`**
- Bind to port 8082 (default API port) before starting launcher
- Start launcher
- Verify graceful error message about port conflict
- Verify exit code is non-zero
- Verify no partial startup (check no PID files exist)

**Test: `TestRandomPortAssignment`**
- Set `LAUNCHER_API_PORT=0` and `LAUNCHER_NATS_PORT=0`
- Start launcher
- Verify it finds and uses available ports
- Verify gateway actually responds on the assigned port

**Value:** Production deployment scenarios often have port conflicts.

---

## High Priority Tests (Should Have)

### 6. Configuration Loading - Environment Variables
**Risk:** Misconfigured services due to env var handling bugs

**Test: `TestEnvVarResolution`**
- Set `LAUNCHER_API_HOST=0.0.0.0`, `LAUNCHER_API_PORT=9999`
- Start launcher
- Verify gateway binds to `0.0.0.0:9999` (check netstat or similar)
- Verify NATS uses defaults (no env vars set)

**Test: `TestEnvVarFallbacks`**
- Clear all LAUNCHER_* env vars
- Start launcher
- Verify it uses defaults (127.0.0.1:8082, etc.)
- Verify services start successfully

**Value:** Configuration is the #1 source of production issues.

---

### 7. .env File Loading for Plugins
**Risk:** Plugins don't receive correct configuration from .env files

**Test: `TestPluginEnvFileLoading`**
- Create `plugins/test-plugin/` directory
- Create `plugins/test-plugin/.env` with `TEST_KEY=test_value`
- Create mock plugin that prints env vars to log
- Start launcher
- Verify log contains `TEST_KEY=test_value`

**Test: `TestPluginEnvOverridePrecedence`**
- Create `.env` with `API_KEY=from_env_file`
- Start launcher with env var `API_KEY=from_runtime`
- Verify plugin receives `API_KEY=from_runtime` (runtime wins)

**Value:** Plugin configuration system must work reliably.

---

### 8. Prebuilt Mode vs Source Mode
**Risk:** Wrong binaries used, builds triggered when prebuilt expected

**Test: `TestPrebuiltModeValidation`**
- Set `LAUNCHER_PREBUILT=1`
- Create `.build/bin/` with mock binaries
- Create `manifest.json` listing those binaries
- Start launcher
- Verify no compilation occurs (no "Building" messages)
- Verify binaries from `.build/bin/` are used

**Test: `TestPrebuiltModeMissingBinary`**
- Set `LAUNCHER_PREBUILT=1`
- Create manifest referencing non-existent binary
- Start launcher
- Verify exits with error about missing binary
- Verify error mentions specific missing component

**Test: `TestSourceModeBuildFailure`**
- Create `plugins/bad-plugin/go.mod` with syntax error
- Start launcher (source mode)
- Verify plugin is skipped with warning
- Verify other plugins and gateway still start

**Value:** CI/CD pipelines rely on prebuilt mode working correctly.

---

### 9. Clean Shutdown with Force Kill Fallback
**Risk:** Services don't terminate, requiring manual cleanup

**Test: `TestGracefulShutdownTimeout`**
- Start launcher with mock service that ignores SIGTERM
- Send SIGTERM to launcher
- Verify launcher waits 2 seconds (grace period)
- Verify launcher sends SIGKILL to stubborn service
- Verify all processes eventually terminate

**Test: `TestLauncherRestart`**
- Start launcher, then run `launcher down` in separate terminal
- Verify original launcher receives signal and shuts down
- Verify all services stop
- Verify can immediately start new launcher instance

**Value:** Prevents zombie processes and manual cleanup.

---

### 10. Plugin Discovery
**Risk:** Plugins not found, wrong directories scanned

**Test: `TestPluginDiscovery`**
- Create 3 valid plugin directories: `plugins/a`, `plugins/b`, `plugins/c`
- Create 1 invalid: `plugins/.hidden`, `plugins/old.del`
- Start launcher
- Verify only a, b, c start (check logs/PID files)
- Verify hidden and .del are ignored

**Test: `TestEmptyPluginDirectory`**
- Start launcher with empty `plugins/` directory
- Verify starts successfully with just gateway
- Verify logs show "0 plugins discovered" or similar

**Value:** Plugin system must be robust to directory contents.

---

## Medium Priority Tests (Nice to Have)

### 11. Runtime Discovery from Gateway
**Risk:** Plugins use wrong NATS URL after gateway reconfiguration

**Test: `TestRuntimeDiscovery`**
- Start gateway on custom NATS port
- Verify launcher queries `/_internal/runtime`
- Verify plugins receive discovered NATS URL, not default

---

### 12. Status Command
**Risk:** Misleading status information

**Test: `TestStatusCommand`**
- Start launcher
- Run `launcher status`
- Verify output lists all running services with correct PIDs
- Kill one service manually
- Run `launcher status` again
- Verify shows stale PID (expected behavior - file-based tracking)

---

### 13. Log File Output
**Risk:** No visibility into service issues

**Test: `TestLogFileCreation`**
- Start launcher
- Verify `.build/logs/` contains:
  - `nats.log`
  - `gateway.log`
  - `<plugin>.log` for each plugin
- Verify logs are append mode (restart launcher, verify old logs preserved)

---

## Test Infrastructure Requirements

### Mock Binaries
Create test fixtures that simulate real services:

```go
// test/fixtures/mock_gateway.go
// Responds to health checks, exposes runtime endpoint

// test/fixtures/mock_plugin.go
// Exits after configurable duration, logs to stdout

// test/fixtures/stubborn_service.go
// Ignores SIGTERM to test force kill logic
```

### Test Helpers

```go
// test/helpers/launcher.go
func StartLauncher(t *testing.T, env map[string]string) *LauncherProcess
func StopLauncher(t *testing.T, proc *LauncherProcess)
func WaitForHealth(t *testing.T, url string, timeout time.Duration)
func GetPID(t *testing.T, name string) int
func KillProcess(t *testing.T, pid int, signal os.Signal)
```

### Isolation
- Each test gets fresh `.build/` directory
- Tests run in parallel by using different port ranges
- Cleanup guarantees (t.Cleanup) to remove processes/files

---

## Test Execution Strategy

| Phase | Tests | Duration | When |
|-------|-------|----------|------|
| Fast | 1, 6, 10 | <30s | Pre-commit |
| Medium | 2, 3, 4, 7 | 2-3min | PR CI |
| Full | 5, 8, 9, 11, 12, 13 | 5min | Release CI |

---

## Coverage Goals

- **Critical (tests 1-5):** Must have 100% pass rate
- **High (tests 6-10):** Should have 100% pass rate
- **Medium (tests 11-13):** Nice to have, can skip in emergency

Focus on **integration tests over unit tests** - the value is in verifying the coordination logic works end-to-end.
