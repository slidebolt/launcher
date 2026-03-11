# Breaking Tests - System Weaknesses Exposed

## Summary

This document describes 20 breaking tests designed to expose weaknesses in the launcher system WITHOUT modifying any production code. These tests document edge cases, race conditions, and error handling gaps that may cause failures in production.

## Test Philosophy

**Breaking tests** are tests that are *designed to fail* and expose weaknesses. They serve as:
- Documentation of known edge cases
- Regression tests once issues are fixed
- Proof of weaknesses for prioritization

## Exposed Weaknesses by Category

---

## 1. Race Conditions & Timing Issues

### TestRapidStartStop
**Exposes:** Lock file cleanup race condition
- **Scenario:** Rapid start/stop cycles
- **Weakness:** Lock file may not be cleaned up before next start attempt
- **Impact:** Second launcher instance fails with "already running" error even after first stopped
- **Likelihood:** Medium (depends on filesystem timing)

### TestStaleLockFile
**Exposes:** Stale lock file handling
- **Scenario:** Launcher crashes, leaving lock file behind
- **Weakness:** `acquireSingleInstance()` may not detect stale locks
- **Impact:** Cannot restart launcher without manual lock file removal
- **Likelihood:** High (crashes happen, manual intervention required)

### TestConcurrentStatusCommands
**Exposes:** File-based state race conditions
- **Scenario:** Multiple status commands while services starting/stopping
- **Weakness:** Reading PID files during write operations
- **Impact:** Status may show inconsistent or partial data
- **Likelihood:** Low (concurrent status commands rare)

### TestSignalDuringStartup
**Exposes:** Signal handling during initialization
- **Scenario:** Ctrl+C pressed during gateway startup delay
- **Weakness:** Partial startup may not cleanup properly
- **Impact:** Lock files and PID files left behind
- **Likelihood:** Medium (users impatient with slow startup)

### TestStopDuringPluginRestart
**Exposes:** Timing window in supervision loop
- **Scenario:** Stop command during 200ms restart delay
- **Weakness:** Plugin process may be orphaned
- **Impact:** Zombie processes left running after launcher exits
- **Likelihood:** Medium (restart delay is small window)

---

## 2. File Handling & Edge Cases

### TestCorruptedPIDFile
**Exposes:** PID file validation weakness
- **Scenario:** PID file contains "not-a-number"
- **Weakness:** May crash or behave unexpectedly when parsing fails
- **Impact:** Unknown - could crash launcher or fail to manage process
- **Likelihood:** Low (requires manual file corruption)

### TestLongPluginName
**Exposes:** Filename length limits
- **Scenario:** Plugin name is 100+ characters
- **Weakness:** May exceed filesystem limits or cause truncation
- **Impact:** PID/log files may not be created correctly
- **Likelihood:** Low (unusual naming)

### TestSpecialCharactersInName
**Exposes:** Filename sanitization gaps
- **Scenario:** Names with dots, multiple hyphens
- **Weakness:** Discovery filtering may miss valid plugins
- **Impact:** Plugins not started despite being present
- **Likelihood:** Medium (semantic versioning common)

---

## 3. Resource & Scaling Issues

### TestManyPlugins
**Exposes:** Scaling limitations
- **Scenario:** 20 plugins starting simultaneously
- **Weakness:** Resource exhaustion, file descriptor limits
- **Impact:** Some plugins may fail to start
- **Likelihood:** Low (rare to have 20+ plugins)

### TestRapidPluginCrash
**Exposes:** Supervisor stability under load
- **Scenario:** Plugin crashes every 50ms
- **Weakness:** Supervisor may stop restarting after many failures
- **Impact:** Service outage if supervisor gives up
- **Likelihood:** Medium (buggy plugins can crash rapidly)

### TestPIDReuse
**Exposes:** PID-based tracking weakness
- **Scenario:** Process dies, PID gets reused by different process
- **Weakness:** Launcher may kill wrong process
- **Impact:** Data loss if wrong process killed
- **Likelihood:** Low (requires PID wraparound)

---

## 4. Error Handling & Edge Cases

### TestPartialStartupCleanup
**Exposes:** Incomplete cleanup on startup failure
- **Scenario:** NATS starts, gateway fails health check
- **Weakness:** NATS process may not be cleaned up
- **Impact:** Resource leak, zombie processes
- **Likelihood:** Medium (startup failures common in development)

### TestMissingPluginEnvFile
**Exposes:** Missing file handling
- **Scenario:** Plugin config directory doesn't exist
- **Weakness:** May crash when trying to read .env files
- **Impact:** Plugin fails to start or launcher crashes
- **Likelihood:** Medium (new plugins often lack config)

### TestEmptyEnvironmentVariables
**Exposes:** Empty string vs unset handling
- **Scenario:** LAUNCHER_API_PORT="" (empty string)
- **Weakness:** `getEnv()` may treat empty string as valid value
- **Impact:** Uses empty string instead of default port
- **Likelihood:** Medium (common user error)

### TestBinaryNotExecutable
**Exposes:** Permission error handling
- **Scenario:** Binary file lacks execute permission
- **Weakness:** May not check permissions before exec
- **Impact:** Cryptic error messages or silent failures
- **Likelihood:** Low (CI/CD usually sets permissions)

---

## 5. Data Validation Issues

### TestInvalidManifest
**Exposes:** JSON parsing error handling
- **Scenario:** manifest.json contains invalid JSON
- **Weakness:** May panic on parse failure
- **Impact:** Launcher crash instead of graceful error
- **Likelihood:** Low (manifest usually machine-generated)

### TestStatusWithNoServices
**Exposes:** UX quality with empty state
- **Scenario:** Running status command when no services
- **Weakness:** Error message may be confusing
- **Impact:** Poor user experience
- **Likelihood:** High (first time users often check status)

---

## Criticality Assessment

| Test | Severity | Likelihood | Risk Score |
|------|----------|------------|------------|
| TestStaleLockFile | HIGH | HIGH | CRITICAL |
| TestPartialStartupCleanup | MEDIUM | MEDIUM | HIGH |
| TestRapidPluginCrash | MEDIUM | MEDIUM | HIGH |
| TestEmptyEnvironmentVariables | MEDIUM | MEDIUM | HIGH |
| TestSignalDuringStartup | MEDIUM | MEDIUM | HIGH |
| TestConcurrentStatusCommands | LOW | LOW | LOW |
| TestPIDReuse | HIGH | LOW | MEDIUM |
| TestManyPlugins | MEDIUM | LOW | LOW |

---

## Recommended Priority Order for Fixes

### Phase 1: Critical (Fix Immediately)
1. **TestStaleLockFile** - Lock file handling with crashes
2. **TestEmptyEnvironmentVariables** - Empty string handling
3. **TestSignalDuringStartup** - Cleanup on interrupt

### Phase 2: High Priority
4. **TestPartialStartupCleanup** - Resource leak on failure
5. **TestRapidPluginCrash** - Supervisor robustness
6. **TestStopDuringPluginRestart** - Orphaned processes

### Phase 3: Nice to Have
7. **TestCorruptedPIDFile** - Validation
8. **TestSpecialCharactersInName** - Discovery
9. **TestStatusWithNoServices** - UX

---

## Running Breaking Tests

```bash
# Run all breaking tests
cd /home/gavin/work/sb/work/raw/launcher
go test -v -run "Test.*" breaking_test.go launcher_test.go test/helpers/helpers.go

# Run specific category
# Race conditions
go test -v -run "TestRapid|TestStale|TestConcurrent|TestSignal|TestStop" breaking_test.go launcher_test.go test/helpers/helpers.go

# File handling
go test -v -run "TestCorrupted|TestLong|TestSpecial" breaking_test.go launcher_test.go test/helpers/helpers.go

# Critical only
go test -v -run "TestStaleLockFile|TestPartialStartup|TestEmptyEnvironment" breaking_test.go launcher_test.go test/helpers/helpers.go
```

---

## Interpreting Results

**Test PASS:** Weakness has been fixed (good!) or test needs refinement
**Test FAIL:** Weakness confirmed and documented
**Test SKIP:** Known limitation or test issue

All failing tests should be triaged and either:
1. Fixed in production code
2. Documented as known limitations
3. Test refined if it's a false positive

---

## Document History

- **Created:** 2026-03-08
- **Purpose:** Document system weaknesses via breaking tests
- **Status:** Tests compile, ready to run against production code
