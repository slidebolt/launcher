# Core Architectural Components and Entry Points

## Overview

This launcher is a process management tool for the Slidebolt ecosystem. It handles service lifecycle, build processes, and supervision in either source or prebuilt mode.

## Core Functional Domains

### 1. Command Entry Points (Main Interface)

**Current Entry Points:**
- `main()` - CLI dispatcher, handles `up`, `down`, `status` commands
- `up()` - Full startup sequence (NATS → Gateway → Plugins → Supervision)
- `down()` - Graceful shutdown of all services
- `status()` - Display running service PIDs

**Simplified Entry Points Proposal:**
- `Start()` - Start all services (was: `up()`)
- `Stop()` - Stop all services (was: `down()`)
- `ListServices()` - Show service status (was: `status()`)

---

### 2. Service Lifecycle Management

**Current Functions:**
- `startNATS()` - Launch NATS server
- `startService(name, bin, env)` - Generic service starter
- `startPluginService(name, bin, env)` - Plugin-specific starter
- `startServiceWithPluginEnv(name, bin, env, pluginEnv)` - Internal implementation
- `supervise(name, bin)` - Restart loop for crashed plugins

**Issues:**
- Three overlapping `start*` functions that could be consolidated
- `supervise()` combines process management with restart logic

**Simplified Contract:**
- `StartService(ServiceConfig) *exec.Cmd` - Unified service starter
- `Supervise(ServiceConfig)` - Watchdog with restart capability

---

### 3. Discovery System

**Current Functions:**
- `discoverPluginPaths(root)` - Find plugin source directories
- `discoverPluginBinaries(root)` - Find prebuilt plugin executables
- `discoverRuntime()` - Query gateway for runtime configuration

**Issues:**
- Inconsistent naming: "discover" vs "discover" with different semantics
- `discoverRuntime()` queries HTTP, others scan filesystem

**Simplified Contract:**
- `ScanPlugins(sourceDir) []PluginInfo` - Find source plugins
- `ScanBinaries(binDir) []string` - Find compiled plugins
- `FetchRuntimeConfig() (RuntimeConfig, bool)` - Get runtime from gateway

---

### 4. Build System

**Current Functions:**
- `isBuildable(path)` - Check if directory is a Go project
- `build(name, path)` - Compile a plugin from source
- `validatePrebuiltBinaries(root, manifestPath)` - Verify manifest against files

**Issues:**
- `isBuildable()` is a predicate, should follow Go naming (no "is" prefix)
- `validatePrebuiltBinaries()` is too long and specific

**Simplified Contract:**
- `CanBuild(path string) bool` - Check buildability (was: `isBuildable`)
- `Compile(output, source string) error` - Build binary (was: `build`)
- `ValidateManifest(manifestPath, binDir string) error` - Check prebuilt integrity

---

### 5. Process Management

**Current Functions:**
- `savePID(name, pid)` - Write PID to file
- `acquireSingleInstance()` - File-based locking
- `releaseSingleInstance()` - Release lock
- `requestStopRunningLauncher()` - Signal existing launcher
- `cleanupLockArtifacts()` - Clean stale locks
- `downServices()` - Kill all tracked processes

**Issues:**
- "SingleInstance" terminology is verbose
- `downServices()` is part of shutdown, should align with `Stop()` naming

**Simplified Contract:**
- `AcquireLock() error` - Get exclusive lock (was: `acquireSingleInstance`)
- `ReleaseLock()` - Drop lock (was: `releaseSingleInstance`)
- `SignalLauncher(pid int) error` - Stop running instance (was: `requestStopRunningLauncher`)
- `KillAll(deadline time.Duration) error` - Terminate services (was: `downServices`)
- `WritePID(name string, pid int) error` - Track process (was: `savePID`)

---

### 6. Environment & Configuration

**Current Functions:**
- `loadConfig()` - Build configuration from environment
- `loadPluginEnv(name)` - Load plugin-specific env files
- `findPluginEnvFiles(name)` - Locate .env files
- `parseDotEnvFile(path)` - Parse .env file format
- `mergedEnv(base, pluginEnv, runtimeEnv)` - Merge environment layers
- `envSlice(m)` - Convert map to slice
- `getEnv(key, fallback)` - Get env with default
- `resolvePort(envKey, fallback)` - Get port with special "0" handling
- `randomFreePort()` - Find available port
- `isPrebuiltMode()` - Check LAUNCHER_PREBUILT env
- `shouldStartNATS()` - Check LAUNCHER_SKIP_NATS env

**Issues:**
- 11 functions scattered across concerns
- Some return strings, others maps, others bools
- `getEnv` collides with standard library `os.Getenv`

**Simplified Contract:**

Configuration Loading:
- `LoadConfig() Config` - Build full configuration (was: `loadConfig`)
- `LoadPluginConfig(name string) map[string]string` - Get plugin env (was: `loadPluginEnv`)

Environment Utilities:
- `Env(key, fallback string) string` - Get with default (was: `getEnv`)
- `Port(key, fallback string) string` - Get port (0 = random) (was: `resolvePort`)
- `RandomPort() string` - Get available port (was: `randomFreePort`)

Mode Detection:
- `PrebuiltMode() bool` - Check mode (was: `isPrebuiltMode`)
- `ExternalNATS() bool` - Check if NATS should be skipped (was: `shouldStartNATS`, inverted)

Environment Processing:
- `MergeEnvs(layers ...map[string]string) []string` - Combine env maps (was: `mergedEnv`, `envSlice`)
- `ParseEnvFile(path string) (map[string]string, error)` - Parse .env (was: `parseDotEnvFile`)

---

### 7. Health Checking

**Current Functions:**
- `waitForGateway()` - Poll gateway until healthy

**Simplified Contract:**
- `WaitForHealthy(url string, timeout time.Duration) bool` - Generic health waiter (was: `waitForGateway`)

---

## Architecture Diagram

```
main()
├── Start()                    [Orchestration]
│   ├── AcquireLock()
│   ├── LoadConfig()
│   ├── StartNATS()            [if !ExternalNATS()]
│   ├── Compile() / UsePrebuilt()
│   ├── StartService(Gateway)
│   ├── WaitForHealthy()
│   ├── FetchRuntimeConfig()
│   └── Supervise(Plugins)
│       └── StartService(Plugin)
├── Stop()                     [Shutdown]
│   ├── SignalLauncher()
│   ├── KillAll()
│   └── ReleaseLock()
└── ListServices()             [Status]
```

## Key Structural Observations

1. **No Types Defined:** All data is passed as primitive strings/maps. Consider creating:
   - `type Service struct { Name, Binary, Env map[string]string }`
   - `type Config struct { APIHost, APIPort, NATSURL string }` (already exists but could expand)

2. **Global State:** `cfg`, `lockHandle`, `ui` are package-level variables. Consider dependency injection.

3. **File Organization:** All 646 lines in single `main.go`. Could separate:
   - `commands.go` - Start, Stop, ListServices
   - `services.go` - Service lifecycle
   - `discovery.go` - Plugin/binary discovery
   - `build.go` - Compilation
   - `process.go` - PID management, locking
   - `config.go` - Environment, configuration
   - `env.go` - .env file parsing
