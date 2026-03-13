package main

import (
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/slidebolt/sdk-runner"
	"github.com/slidebolt/sdk-types"
)

var ui = runner.NewTheme()

// cmdUp starts the full Slidebolt stack and supervises it until a signal arrives.
func cmdUp(cfg Config) {
	if err := acquireLock(cfg); err != nil {
		logger.Error("launcher already running", "error", err)
		os.Exit(1)
	}
	defer releaseLock(cfg)

	if err := writeLauncherPID(cfg); err != nil {
		logger.Error("failed writing PID file", "error", err)
		os.Exit(1)
	}
	defer os.Remove(cfg.PIDFile)

	// Register signal handling immediately so that signals arriving during
	// startup (health-check wait, build) still trigger a clean shutdown.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	setupDirs(cfg)

	sup := NewSupervisor(cfg)

	// Step 1: Infrastructure (NATS)
	if cfg.StartNATS {
		fmt.Println(ui.Step(1, "Infrastructure", "Starting NATS..."))
		if err := sup.Start(natsService(cfg)); err != nil {
			logger.Error("NATS start failed", "error", err)
			sup.StopAll()
			os.Exit(1)
		}
	} else {
		fmt.Println(ui.Step(1, "Infrastructure", "Using external NATS..."))
	}

	// Step 2: Gateway
	if cfg.Prebuilt {
		if err := validatePrebuiltBinaries(cfg.BinDir, "manifest.json"); err != nil {
			logger.Error("prebuilt binary validation failed", "error", err)
			sup.StopAll()
			os.Exit(1)
		}
		fmt.Println(ui.Step(2, "Gateway", "Starting prebuilt gateway..."))
	} else {
		fmt.Println(ui.Step(2, "Gateway", "Building and starting..."))
		if err := Build("gateway", "gateway", cfg.BinDir); err != nil {
			logger.Error("gateway build failed", "error", err)
			sup.StopAll()
			os.Exit(1)
		}
	}

	if err := sup.Start(gatewayService(cfg)); err != nil {
		logger.Error("gateway start failed", "error", err)
		sup.StopAll()
		os.Exit(1)
	}

	if !WaitUntilHealthy(cfg.APIURL+types.RPCMethodHealthCheck, 8*time.Second) {
		logger.Error("gateway failed health check")
		sup.StopAll()
		os.Exit(1)
	}
	logger.Info("gateway verified", "status", "healthy")

	if natsURL, ok := DiscoverRuntime(cfg.APIURL); ok {
		cfg.NATSURL = natsURL
		logger.Info("runtime discovered", "nats", cfg.NATSURL)
	}

	// Step 3: Plugins (supervised)
	if cfg.Prebuilt {
		fmt.Println(ui.Step(3, "Plugins", "Starting prebuilt plugins..."))
		for _, name := range discoverPluginBinaries(cfg.BinDir) {
			if err := sup.Start(pluginService(cfg, name, filepath.Join(cfg.BinDir, name))); err != nil {
				logger.Warn("plugin start failed", "name", name, "error", err)
			}
		}
	} else {
		fmt.Println(ui.Step(3, "Plugins", "Building and supervising..."))
		var skipped []string
		for _, path := range discoverPluginPaths("plugins") {
			name := filepath.Base(path)
			if err := Build(name, path, cfg.BinDir); err != nil {
				logger.Warn("plugin build failed", "name", name, "error", err)
				skipped = append(skipped, name)
				continue
			}
			if err := sup.Start(pluginService(cfg, name, filepath.Join(cfg.BinDir, name))); err != nil {
				logger.Warn("plugin start failed", "name", name, "error", err)
				skipped = append(skipped, name)
			}
		}
		if len(skipped) > 0 {
			logger.Warn("skipped plugins", "names", strings.Join(skipped, ", "))
		}
	}

	logger.Info("stack is up")

	<-sigCh

	logger.Warn("shutting down")
	sup.StopAll()
}

// cmdDown signals the running launcher to shut down and waits. If no launcher
// is running, it cleans up any orphaned PID files and lock artifacts.
func cmdDown(cfg Config) {
	pid := readPIDFile(cfg.PIDFile)
	if pid > 0 && syscall.Kill(pid, 0) == nil {
		logger.Info("sending SIGTERM to launcher", "pid", pid)
		syscall.Kill(pid, syscall.SIGTERM)

		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			if syscall.Kill(pid, 0) != nil {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
		if syscall.Kill(pid, 0) == nil {
			logger.Warn("launcher did not exit, force killing")
			syscall.Kill(pid, syscall.SIGKILL)
		}
	} else {
		cleanOrphanedPIDs(cfg)
	}
	logger.Info("all services stopped")
}

// cmdStatus prints the state of every service tracked by a PID file,
// including whether the process is currently alive.
func cmdStatus(cfg Config) {
	sup := NewSupervisor(cfg)
	statuses := sup.Status()
	if len(statuses) == 0 {
		logger.Info("no services running")
		return
	}
	fmt.Println(ui.Title("Service Status"))
	for _, s := range statuses {
		liveness := ui.Value("alive")
		if !s.Alive {
			liveness = ui.Warn("dead (stale PID)")
		}
		fmt.Printf("%s: %s %d  %s\n",
			ui.Key(s.Name),
			ui.Muted("PID"),
			s.PID,
			liveness,
		)
	}
}

// --- Service constructors ---

func natsService(cfg Config) *ManagedService {
	natsBin := "nats-server"
	if _, err := exec.LookPath(natsBin); err != nil {
		natsBin = filepath.Join(os.Getenv("HOME"), "go/bin/nats-server")
	}

	// Parse host and port from nats://host:port
	addr := strings.TrimPrefix(cfg.NATSURL, "nats://")
	parts := strings.SplitN(addr, ":", 2)
	host, port := "127.0.0.1", "4224"
	if len(parts) == 2 {
		host, port = parts[0], parts[1]
	}

	natsDataDir := filepath.Join(cfg.DataDir, "nats")
	os.MkdirAll(natsDataDir, 0o755)

	return &ManagedService{
		Name:    "nats",
		Binary:  natsBin,
		Args:    []string{"-a", host, "-p", port, "-js", "-sd", natsDataDir},
		Env:     os.Environ(),
		Restart: false,
	}
}

func gatewayService(cfg Config) *ManagedService {
	rpcSubject := types.SubjectRPCPrefix + cfg.CorePluginID
	return &ManagedService{
		Name:    "gateway",
		Binary:  filepath.Join(cfg.BinDir, "gateway"),
		Env:     mergedEnv(os.Environ(), nil, map[string]string{
			types.EnvAPIPort:       cfg.APIPort,
			types.EnvAPIHost:       cfg.APIHost,
			types.EnvNATSURL:       cfg.NATSURL,
			types.EnvPluginRPCSbj:  rpcSubject,
			types.EnvPluginDataDir: filepath.Join(cfg.DataDir, "gateway"),
			types.EnvRuntimeFile:   filepath.Join(cfg.BuildDir, "runtime.json"),
		}),
		Restart: false,
	}
}

func pluginService(cfg Config, name, binary string) *ManagedService {
	dataDir := filepath.Join(cfg.DataDir, name)
	logger.Debug("plugin service configured", "name", name, "binary", binary, "data_dir", dataDir)
	runtimeEnv := map[string]string{
		types.EnvNATSURL:       cfg.NATSURL,
		types.EnvPluginRPCSbj:  types.SubjectRPCPrefix + name,
		types.EnvPluginDataDir: dataDir,
	}
	return &ManagedService{
		Name:    name,
		Binary:  binary,
		Env:     pluginEnv(name, runtimeEnv),
		Restart: true,
	}
}

// --- Lock and PID helpers ---

var lockHandle *os.File

func acquireLock(cfg Config) error {
	f, err := os.OpenFile(cfg.LockFile, os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		return err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return fmt.Errorf("lock %s is held by another launcher", cfg.LockFile)
	}
	lockHandle = f
	return nil
}

func releaseLock(cfg Config) {
	if lockHandle == nil {
		return
	}
	syscall.Flock(int(lockHandle.Fd()), syscall.LOCK_UN)
	lockHandle.Close()
	lockHandle = nil
	os.Remove(cfg.LockFile)
}

func writeLauncherPID(cfg Config) error {
	return os.WriteFile(cfg.PIDFile, []byte(strconv.Itoa(os.Getpid())), 0o644)
}

func readPIDFile(path string) int {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	pid, _ := strconv.Atoi(strings.TrimSpace(string(data)))
	return pid
}

func cleanOrphanedPIDs(cfg Config) {
	files, _ := filepath.Glob(filepath.Join(cfg.PIDDir, "*.pid"))
	for _, f := range files {
		os.Remove(f)
	}
	os.Remove(cfg.LockFile)
	os.Remove(cfg.PIDFile)
}

func setupDirs(cfg Config) {
	if cfg.Prebuilt {
		for _, d := range []string{cfg.LogDir, cfg.PIDDir, cfg.DataDir} {
			os.MkdirAll(d, 0o755)
		}
	} else {
		os.RemoveAll(cfg.BuildDir)
		for _, d := range []string{cfg.BinDir, cfg.LogDir, cfg.PIDDir, cfg.DataDir} {
			os.MkdirAll(d, 0o755)
		}
	}
}
