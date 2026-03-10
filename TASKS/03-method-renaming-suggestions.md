# Method Renaming Suggestions for Simplified Contracts

## Summary

This document provides specific rename suggestions to clarify intent and simplify the API surface area while maintaining 100% functionality.

---

## Command Interface (Main Entry Points)

| Current | Proposed | Rationale |
|---------|----------|-----------|
| `up()` | `Start()` | Clearer verb, consistent with command name |
| `down()` | `Stop()` | Symmetric with `Start()`, clearer intent |
| `status()` | `ListServices()` | Active voice, describes action not state |

---

## Service Lifecycle

| Current | Proposed | Rationale |
|---------|----------|-----------|
| `startService(name, bin, env)` | `StartService(cfg ServiceConfig)` | Use config struct instead of 3 params |
| `startPluginService(name, bin, env)` | *(merge into StartService)* | Remove duplicate, handle via config |
| `startServiceWithPluginEnv(...)` | *(internal, keep private)* | Already an implementation detail |
| `startNATS()` | `StartNATS()` | Keep name, but return `*exec.Cmd` for consistency |
| `supervise(name, bin)` | `Supervise(cfg ServiceConfig)` | Unified signature, restart loop stays |

**New Type Needed:**
```go
type ServiceConfig struct {
    Name      string
    Binary    string
    Env       map[string]string
    PluginEnv map[string]string  // optional, merged at lower precedence
    LogFile   string             // optional, defaults to name.log
}
```

---

## Discovery System

| Current | Proposed | Rationale |
|---------|----------|-----------|
| `discoverPluginPaths(root)` | `ScanPlugins(dir string) []PluginInfo` | "Scan" implies filesystem, returns typed data |
| `discoverPluginBinaries(root)` | `ScanBinaries(dir string) []PluginInfo` | Consistent "Scan" prefix, simpler return |
| `discoverRuntime()` | `FetchRuntime() (RuntimeConfig, bool)` | "Fetch" implies network/API call |

**New Types:**
```go
type PluginInfo struct {
    Name string
    Path string
    Source bool  // true = source dir, false = prebuilt binary
}

type RuntimeConfig struct {
    NATSURL string
    // room for expansion
}
```

---

## Build System

| Current | Proposed | Rationale |
|---------|----------|-----------|
| `isBuildable(path)` | `CanBuild(path string) bool` | Go style: predicate functions don't use "is" prefix |
| `build(name, path)` | `Compile(output, source string) error` | "Compile" is more precise than "build" |
| `validatePrebuiltBinaries(root, manifest)` | `ValidateManifest(manifest, binDir string) error` | Shorter, parameter order matches logic |

---

## Process Management

| Current | Proposed | Rationale |
|---------|----------|-----------|
| `savePID(name, pid)` | `WritePID(name string, pid int) error` | "Write" is clearer than "save", add error return |
| `acquireSingleInstance()` | `AcquireLock() error` | Remove verbose "SingleInstance" |
| `releaseSingleInstance()` | `ReleaseLock()` | Symmetric with AcquireLock |
| `requestStopRunningLauncher()` | `SignalLauncher(sig os.Signal) error` | More flexible, accepts signal type |
| `cleanupLockArtifacts()` | `CleanupLock()` | Shorter, "artifacts" is unnecessary |
| `downServices()` | `KillAll(timeout time.Duration) error` | Active voice, explicit timeout parameter |

---

## Configuration & Environment

| Current | Proposed | Rationale |
|---------|----------|-----------|
| `loadConfig()` | `LoadConfig() Config` | Build full configuration (was: `loadConfig`)
| `loadPluginEnv(name)` | `LoadPluginConfig(name string) (Config, error)` | Returns typed data, adds error handling |
| `findPluginEnvFiles(name)` | `findEnvFiles(name string) []string` | Keep private, simpler name |
| `parseDotEnvFile(path)` | `ParseEnvFile(path string) (map[string]string, error)` | General "EnvFile" not "DotEnv" |
| `getEnv(key, fallback)` | `Env(key, fallback string) string` | Shorter, distinct from os.Getenv |
| `resolvePort(envKey, fallback)` | `Port(key, fallback string) string` | Shorter, behavior unchanged |
| `randomFreePort()` | `RandomPort() string` | Shorter, "Free" is implied |
| `isPrebuiltMode()` | `PrebuiltMode() bool` | Go predicate style |
| `shouldStartNATS()` | `ExternalNATS() bool` | Invert logic: returns true if using external |
| `mergedEnv(base, plugin, runtime)` | `MergeEnvs(layers ...map[string]string) []string` | Variadic, cleaner precedence (left-to-right) |
| `envSlice(m)` | *(inline into MergeEnvs)* | Single-use helper, eliminate |

---

## Health Checking

| Current | Proposed | Rationale |
|---------|----------|-----------|
| `waitForGateway()` | `WaitForHealthy(url string, timeout time.Duration) bool` | Generic, accepts any URL |

---

## Rename Impact Summary

### Total Functions: 35
- **Keep As-Is:** 2 (`main`, `setupDirs` - already clear)
- **Rename Only:** 22 functions get clearer names
- **Merge Duplicates:** 3 functions consolidated (`startService` variants)
- **Eliminate:** 1 function (`envSlice` - inline)
- **Add Types:** 3 new config structs (ServiceConfig, PluginInfo, RuntimeConfig)

### Result: 31 functions with simplified, consistent naming

---

## Naming Patterns Established

After renaming, the API follows these consistent patterns:

| Pattern | Examples | Use For |
|---------|----------|---------|
| **VerbNoun** | `StartService`, `StopNATS`, `WritePID` | Actions that do work |
| **Can/Has/Is** | `CanBuild`, `PrebuiltMode`, `ExternalNATS` | Boolean predicates |
| **Noun** | `LoadConfig`, `FetchRuntime` | Data loading |
| **Scan/Fetch** | `ScanPlugins`, `FetchRuntime` | Discovery (filesystem vs network) |

---

## Example Before/After

### Before:
```go
func up() {
    cfg = loadConfig()
    startNATS()
    build("gateway", "gateway")
    startService("gateway", bin, env)
    if !waitForGateway() { ... }
    for _, path := range discoverPluginPaths("plugins") {
        build(name, path)
        go supervise(name, bin)
    }
}
```

### After:
```go
func Start() {
    cfg = LoadConfig()
    StartNATS()
    Compile("gateway", "gateway")
    StartService(ServiceConfig{Name: "gateway", Binary: bin, Env: env})
    if !WaitForHealthy(url, 8*time.Second) { ... }
    for _, plugin := range ScanPlugins("plugins") {
        Compile(plugin.Name, plugin.Path)
        go Supervise(ServiceConfig{Name: plugin.Name, Binary: bin})
    }
}
```
