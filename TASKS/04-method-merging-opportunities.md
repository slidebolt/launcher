# Method Merging and Consolidation Opportunities

## Summary

This document identifies overlapping functionality that could be merged to reduce API surface area and improve maintainability.

---

## 1. Service Start Functions (High Priority)

### Current State: 3 Functions with Overlapping Logic

```go
func startService(name, bin string, env map[string]string) *exec.Cmd {
    return startServiceWithPluginEnv(name, bin, env, nil)
}

func startPluginService(name, bin string, env map[string]string) *exec.Cmd {
    pluginEnv := loadPluginEnv(name)
    return startServiceWithPluginEnv(name, bin, env, pluginEnv)
}

func startServiceWithPluginEnv(name, bin string, env map[string]string, pluginEnv map[string]string) *exec.Cmd {
    // ... 15 lines of implementation
}
```

### Issues:
- `startService` is just a wrapper that passes `nil` pluginEnv
- `startPluginService` does env loading then delegates
- `startServiceWithPluginEnv` is the real implementation but has awkward name

### Proposed Merge:

**Single Function:**
```go
func StartService(cfg ServiceConfig) *exec.Cmd

type ServiceConfig struct {
    Name      string
    Binary    string
    Env       map[string]string  // runtime env (highest precedence)
    LoadEnv   bool               // if true, load plugin .env files
}
```

**Usage:**
```go
// Gateway (no plugin env)
StartService(ServiceConfig{
    Name:    "gateway",
    Binary:  binPath,
    Env:     gatewayEnv,
    LoadEnv: false,
})

// Plugin (with .env files)
StartService(ServiceConfig{
    Name:    name,
    Binary:  binPath,
    Env:     pluginEnv,
    LoadEnv: true,  // triggers loadPluginEnv internally
})
```

**Benefits:**
- Single function instead of 3
- Configuration over parameters
- Plugin env loading becomes internal detail
- Easier to extend (add more config options)

---

## 2. Discovery Functions (Medium Priority)

### Current State: 3 Functions with Similar Structure

```go
func discoverPluginPaths(root string) []string      // scans plugins/ directory
func discoverPluginBinaries(root string) []string  // scans bin/ directory  
func discoverRuntime() (config, bool)              // queries HTTP endpoint
```

### Issues:
- Two filesystem scanners with nearly identical logic
- Different return types (strings vs config struct)
- One is network-based, others are filesystem-based

### Proposed Merge - Option A (Unified Scanner):

```go
type PluginInfo struct {
    Name   string
    Path   string
    Source bool  // true = source, false = binary
}

type Discovery interface {
    Discover() ([]PluginInfo, error)
}

// FileSystemDiscovery implements Discovery
type FileSystemDiscovery struct {
    Root      string
    Pattern   string  // e.g., "plugin-*" for binaries, check go.mod for source
    Filter    func(fs.DirEntry) bool
}

// RuntimeDiscovery implements Discovery
type RuntimeDiscovery struct {
    URL string
}

func (d FileSystemDiscovery) Discover() ([]PluginInfo, error)
func (d RuntimeDiscovery) Discover() (RuntimeConfig, error)
```

### Proposed Merge - Option B (Simpler, Keep Separate but Consistent):

```go
func ScanSources(dir string) []PluginInfo    // was: discoverPluginPaths
func ScanBinaries(dir string) []PluginInfo   // was: discoverPluginBinaries (returns []PluginInfo)
func FetchRuntime() (RuntimeConfig, bool)     // was: discoverRuntime (different return is OK - network)
```

**Recommendation:** Option B - simpler, no interface overhead needed for this CLI tool.

---

## 3. Environment Functions (Medium Priority)

### Current State: 11 Functions Scattered Across Concerns

**Loading:**
- `loadConfig()` - builds config from env vars
- `loadPluginEnv(name)` - loads .env files for plugin
- `findPluginEnvFiles(name)` - locates .env files
- `parseDotEnvFile(path)` - parses .env format

**Utilities:**
- `getEnv(key, fallback)` - env with default
- `resolvePort(envKey, fallback)` - port with "0" = random
- `randomFreePort()` - find free port

**Mode Detection:**
- `isPrebuiltMode()` - check LAUNCHER_PREBUILT
- `shouldStartNATS()` - check LAUNCHER_SKIP_NATS

**Processing:**
- `mergedEnv(base, plugin, runtime)` - merge env layers
- `envSlice(m)` - map → slice conversion

### Proposed Consolidation:

**Package: `config`**

```go
// Loading
func Load() Config
func LoadPlugin(name string) (map[string]string, error)

// Utilities  
func Getenv(key, fallback string) string
func Port(key, fallback string) string  // handles "0" → random

// Mode Detection
func PrebuiltMode() bool
func UseEmbeddedNATS() bool  // inverted from shouldStartNATS

// Processing
func Merge(layers ...map[string]string) []string  // absorbs envSlice
```

**Merged:** `loadConfig` + `loadPluginEnv` + `findPluginEnvFiles` + `parseDotEnvFile` → `Load`, `LoadPlugin`

**Note:** `randomFreePort()` stays separate - it's a distinct networking utility.

---

## 4. Process/Lock Management (Low Priority)

### Current State: 6 Functions

```go
func savePID(name string, pid int)
func acquireSingleInstance() error
func releaseSingleInstance()
func requestStopRunningLauncher()
func cleanupLockArtifacts()
func downServices()
```

### Issues:
- Lock functions are pairs that should stay together
- `cleanupLockArtifacts` is a specific cleanup case
- `downServices` is actually a bulk kill operation

### Proposed Consolidation:

**Create `LockManager` type:**

```go
type LockManager struct {
    lockFile string
    handle   *os.File
}

func (lm *LockManager) Acquire() error
func (lm *LockManager) Release()
func (lm *LockManager) Cleanup()  // absorbs cleanupLockArtifacts
func (lm *LockManager) Signal(sig os.Signal) error  // absorbs requestStopRunningLauncher
```

**Keep Separate:**
- `savePID(name, pid)` → `PIDWriter.Write(name, pid)` (consider if worth typing)
- `downServices()` → `KillAll(timeout)` (bulk operation, distinct concern)

---

## 5. Setup Functions (Low Priority)

### Current State: 2 Functions

```go
func setupDirs(prebuilt bool)
func isBuildable(path string) bool
```

These are distinct concerns and should stay separate.

However, `setupDirs` could be clearer:

```go
func SetupWorkspace(mode RunMode)  // where RunMode = SourceMode or PrebuiltMode

type RunMode int
const (
    SourceMode RunMode = iota
    PrebuiltMode
)
```

---

## Merge Summary Table

| Group | Current Functions | Merged To | Reduction |
|-------|------------------|-----------|-----------|
| Service Start | 3 (`startService`, `startPluginService`, `startServiceWithPluginEnv`) | 1 (`StartService`) | -2 |
| Environment | 4 (`loadConfig` internals) | 2 (`Load`, `LoadPlugin`) | -2 |
| Env Processing | 2 (`mergedEnv`, `envSlice`) | 1 (`Merge`) | -1 |
| Lock Management | 4 (lock-related) | 1 type (`LockManager` with 4 methods) | Conceptual |
| **Total** | **13 functions** | **6 functions + 1 type** | **~50% reduction** |

---

## Recommended Implementation Order

1. **Phase 1:** Merge service start functions (immediate impact, simplifies main flow)
2. **Phase 2:** Consolidate environment loading (reduces env-related complexity)
3. **Phase 3:** Create LockManager type (organizes related functions)
4. **Phase 4:** Unify discovery return types (consistency improvement)

---

## Post-Merge Architecture

```
main.go
├── Start() / Stop() / ListServices()        [Commands]
├── StartService(cfg) / Supervise(cfg)       [Service Lifecycle]
├── StartNATS()                              [Infrastructure]
├── Compile() / CanBuild() / ValidateManifest() [Build]
├── ScanSources() / ScanBinaries() / FetchRuntime() [Discovery]
├── WaitForHealthy()                         [Health]
├── LockManager (type)                       [Process Management]
├── KillAll()                                [Bulk Operations]
└── config package                           [Configuration]
    ├── Load() / LoadPlugin()
    ├── Getenv() / Port()
    ├── PrebuiltMode() / UseEmbeddedNATS()
    └── Merge()
```

**Result:** From ~35 functions to ~20 functions with clearer organization.
