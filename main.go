package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/slidebolt/sdk-runner"
)

const (
	buildDir        = ".build"
	binDir          = ".build/bin"
	logDir          = ".build/logs"
	pidDir          = ".build/pids"
	dataDir         = ".build/data"
	launcherPIDFile = ".launcher.pid"
	launcherLock    = ".launcher.lock"
)

type config struct {
	APIHost      string `json:"api_host"`
	APIPort      string `json:"api_port"`
	APIBaseURL   string `json:"api_base_url"`
	NATSHost     string `json:"nats_host"`
	NATSPort     string `json:"nats_port"`
	NATSURL      string `json:"nats_url"`
	CorePluginID string `json:"core_plugin_id"`
}

var cfg config
var lockHandle *os.File

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: launcher [up|down|status]")
		os.Exit(1)
	}

	cfg = loadConfig()

	switch os.Args[1] {
	case "up":
		up()
	case "down":
		down()
	case "status":
		status()
	default:
		fmt.Printf("unknown command: %s\n", os.Args[1])
		os.Exit(1)
	}
}

func loadConfig() config {
	apiHost := getEnv("LAUNCHER_API_HOST", "127.0.0.1")
	natsHost := getEnv("LAUNCHER_NATS_HOST", "127.0.0.1")
	apiPort := resolvePort("LAUNCHER_API_PORT", "8082")
	natsPort := resolvePort("LAUNCHER_NATS_PORT", "4224")
	corePluginID := getEnv("LAUNCHER_CORE_PLUGIN_ID", "gateway")
	return config{
		APIHost:      apiHost,
		APIPort:      apiPort,
		APIBaseURL:   fmt.Sprintf("http://%s:%s", apiHost, apiPort),
		NATSHost:     natsHost,
		NATSPort:     natsPort,
		NATSURL:      fmt.Sprintf("nats://%s:%s", natsHost, natsPort),
		CorePluginID: corePluginID,
	}
}

func up() {
	if err := acquireSingleInstance(); err != nil {
		fmt.Printf("launcher already running: %v\n", err)
		os.Exit(1)
	}
	defer releaseSingleInstance()

	if err := os.WriteFile(launcherPIDFile, []byte(strconv.Itoa(os.Getpid())), 0o644); err != nil {
		fmt.Printf("failed writing %s: %v\n", launcherPIDFile, err)
		os.Exit(1)
	}
	defer os.Remove(launcherPIDFile)

	prebuilt := isPrebuiltMode()
	setupDirs(prebuilt)

	if shouldStartNATS() {
		fmt.Println("1. Infrastructure: Starting NATS...")
		startNATS()
	} else {
		fmt.Println("1. Infrastructure: Using external NATS...")
	}

	if prebuilt {
		fmt.Println("2. Gateway: Starting prebuilt gateway...")
	} else {
		fmt.Println("2. Gateway: Building and starting...")
		if err := build("gateway", "gateway"); err != nil {
			fmt.Printf("CRITICAL: gateway build failed: %v\n", err)
			downServices()
			os.Exit(1)
		}
	}
	coreRPCSubject := runner.SubjectRPCPrefix + cfg.CorePluginID
	startService("gateway", filepath.Join(binDir, "gateway"), map[string]string{
		runner.EnvAPIPort:      cfg.APIPort,
		runner.EnvAPIHost:      cfg.APIHost,
		runner.EnvNATSURL:      cfg.NATSURL,
		runner.EnvPluginRPCSbj: coreRPCSubject,
		runner.EnvPluginData:   filepath.Join(dataDir, "gateway"),
		runner.EnvRuntimeFile:  filepath.Join(buildDir, "runtime.json"),
	})

	if !waitForGateway() {
		fmt.Println("CRITICAL: Gateway failed health check.")
		downServices()
		os.Exit(1)
	}
	fmt.Println("Gateway verified: PERFECT.")

	if discovered, ok := discoverRuntime(); ok {
		cfg.NATSURL = discovered.NATSURL
		fmt.Printf("Runtime discovered: nats=%s\n", cfg.NATSURL)
	}

	if prebuilt {
		fmt.Println("3. Plugins: Starting prebuilt plugins...")
		for _, name := range discoverPluginBinaries(binDir) {
			go supervise(name, filepath.Join(binDir, name))
		}
	} else {
		fmt.Println("3. Plugins: Building and supervising...")
		skipped := make([]string, 0)
		for _, path := range discoverPluginPaths("plugins") {
			name := filepath.Base(path)
			if err := build(name, path); err != nil {
				fmt.Printf("[skip] plugin build failed [%s]: %v\n", name, err)
				skipped = append(skipped, name)
				continue
			}
			go supervise(name, filepath.Join(binDir, name))
		}
		if len(skipped) > 0 {
			fmt.Printf("Skipped plugins due to build errors: %s\n", strings.Join(skipped, ", "))
		}
	}

	fmt.Println("\nGateway is up. Supervision active.")
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
	downServices()
}

func waitForGateway() bool {
	client := http.Client{Timeout: 200 * time.Millisecond}
	url := cfg.APIBaseURL + runner.HealthEndpoint
	for i := 0; i < 40; i++ {
		resp, err := client.Get(url)
		if err == nil && resp.StatusCode == http.StatusOK {
			resp.Body.Close()
			return true
		}
		if resp != nil {
			resp.Body.Close()
		}
		time.Sleep(200 * time.Millisecond)
	}
	return false
}

func discoverRuntime() (config, bool) {
	client := http.Client{Timeout: 500 * time.Millisecond}
	resp, err := client.Get(cfg.APIBaseURL + "/_internal/runtime")
	if err != nil || resp.StatusCode != http.StatusOK {
		if resp != nil {
			resp.Body.Close()
		}
		return config{}, false
	}
	defer resp.Body.Close()
	var discovered config
	if err := json.NewDecoder(resp.Body).Decode(&discovered); err != nil || discovered.NATSURL == "" {
		return config{}, false
	}
	return discovered, true
}

func supervise(name, bin string) {
	for {
		fmt.Printf("[%s] starting...\n", name)
		cmd := startPluginService(name, bin, map[string]string{
			runner.EnvNATSURL:    cfg.NATSURL,
			runner.EnvPluginData: filepath.Join(dataDir, name),
		})
		if cmd == nil {
			return
		}
		fmt.Printf("[%s] PID %d\n", name, cmd.Process.Pid)
		cmd.Wait()

		if _, err := os.Stat(filepath.Join(pidDir, name+".pid")); err != nil {
			fmt.Printf("[%s] stopped\n", name)
			return
		}
		fmt.Printf("[%s] restarting in 200ms...\n", name)
		time.Sleep(200 * time.Millisecond)
	}
}

func setupDirs(prebuilt bool) {
	if prebuilt {
		for _, d := range []string{logDir, pidDir, dataDir} {
			os.MkdirAll(d, 0o755)
		}
		return
	}
	os.RemoveAll(buildDir)
	for _, d := range []string{binDir, logDir, pidDir, dataDir} {
		os.MkdirAll(d, 0o755)
	}
}

func discoverPluginPaths(root string) []string {
	entries, _ := os.ReadDir(root)
	var paths []string
	for _, entry := range entries {
		path := filepath.Join(root, entry.Name())
		if !entry.IsDir() {
			info, err := os.Stat(path)
			if err != nil || !info.IsDir() {
				continue
			}
		}
		name := entry.Name()
		if strings.HasPrefix(name, ".") || strings.HasSuffix(name, ".del") {
			continue
		}
		if isBuildable(path) {
			paths = append(paths, path)
		}
	}
	return paths
}

func discoverPluginBinaries(root string) []string {
	entries, _ := os.ReadDir(root)
	paths := make([]string, 0)
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasPrefix(name, "plugin-") {
			continue
		}
		paths = append(paths, name)
	}
	return paths
}

func isBuildable(path string) bool {
	_, errMod := os.Stat(filepath.Join(path, "go.mod"))
	_, errMain := os.Stat(filepath.Join(path, "main.go"))
	return errMod == nil && errMain == nil
}

func build(name, path string) error {
	out, _ := filepath.Abs(filepath.Join(binDir, name))
	cmd := exec.Command("go", "build", "-o", out, ".")
	cmd.Dir = path
	goWork := "auto"
	if abs, err := filepath.Abs("go.work"); err == nil {
		if _, statErr := os.Stat(abs); statErr == nil {
			goWork = abs
		}
	}
	cmd.Env = append(os.Environ()[:len(os.Environ()):len(os.Environ())], "GOWORK="+goWork)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%s", strings.TrimSpace(string(output)))
	}
	return nil
}

func startNATS() {
	natsBin := "nats-server"
	if _, err := exec.LookPath(natsBin); err != nil {
		natsBin = filepath.Join(os.Getenv("HOME"), "go/bin/nats-server")
	}
	logFile, _ := os.Create(filepath.Join(logDir, "nats.log"))
	cmd := exec.Command(natsBin, "-a", cfg.NATSHost, "-p", cfg.NATSPort)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Pdeathsig: syscall.SIGTERM,
	}
	if err := cmd.Start(); err == nil {
		savePID("nats", cmd.Process.Pid)
	}
}

func startService(name, bin string, env map[string]string) *exec.Cmd {
	return startServiceWithPluginEnv(name, bin, env, nil)
}

func startPluginService(name, bin string, env map[string]string) *exec.Cmd {
	pluginEnv := loadPluginEnv(name)
	return startServiceWithPluginEnv(name, bin, env, pluginEnv)
}

func startServiceWithPluginEnv(name, bin string, env map[string]string, pluginEnv map[string]string) *exec.Cmd {
	os.MkdirAll(filepath.Join(dataDir, name), 0o755)
	logFile, _ := os.OpenFile(filepath.Join(logDir, name+".log"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)

	cmd := exec.Command(bin)
	cmd.Env = mergedEnv(os.Environ(), pluginEnv, env)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Pdeathsig: syscall.SIGTERM,
	}
	if err := cmd.Start(); err != nil {
		return nil
	}
	savePID(name, cmd.Process.Pid)
	return cmd
}

func down() {
	requestStopRunningLauncher()
	downServices()
	cleanupLockArtifacts()
	fmt.Println("All services stopped.")
}

func downServices() {
	files, _ := filepath.Glob(filepath.Join(pidDir, "*.pid"))
	for _, f := range files {
		data, _ := os.ReadFile(f)
		pid, _ := strconv.Atoi(strings.TrimSpace(string(data)))
		syscall.Kill(pid, syscall.SIGTERM)
	}
	deadline := time.Now().Add(2 * time.Second)
	for _, f := range files {
		data, _ := os.ReadFile(f)
		pid, _ := strconv.Atoi(strings.TrimSpace(string(data)))
		for time.Now().Before(deadline) {
			if syscall.Kill(pid, 0) != nil {
				break
			}
			time.Sleep(50 * time.Millisecond)
		}
		if syscall.Kill(pid, 0) == nil {
			syscall.Kill(pid, syscall.SIGKILL)
		}
		os.Remove(f)
	}
}

func status() {
	files, _ := filepath.Glob(filepath.Join(pidDir, "*.pid"))
	if len(files) == 0 {
		fmt.Println("No services running.")
		return
	}
	for _, f := range files {
		data, _ := os.ReadFile(f)
		fmt.Printf("%s: PID %s\n", strings.TrimSuffix(filepath.Base(f), ".pid"), strings.TrimSpace(string(data)))
	}
}

func envSlice(m map[string]string) []string {
	s := make([]string, 0, len(m))
	for k, v := range m {
		s = append(s, k+"="+v)
	}
	return s
}

func savePID(name string, pid int) {
	os.WriteFile(filepath.Join(pidDir, name+".pid"), []byte(strconv.Itoa(pid)), 0o644)
}

func acquireSingleInstance() error {
	f, err := os.OpenFile(launcherLock, os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		return err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return fmt.Errorf("lock %s is held by another launcher", launcherLock)
		}
		return err
	}
	lockHandle = f
	return nil
}

func releaseSingleInstance() {
	if lockHandle == nil {
		return
	}
	_ = syscall.Flock(int(lockHandle.Fd()), syscall.LOCK_UN)
	_ = lockHandle.Close()
	lockHandle = nil
	_ = os.Remove(launcherLock)
}

func requestStopRunningLauncher() {
	data, err := os.ReadFile(launcherPIDFile)
	if err != nil {
		return
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || pid <= 0 || pid == os.Getpid() {
		return
	}
	_ = syscall.Kill(pid, syscall.SIGTERM)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if syscall.Kill(pid, 0) != nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if syscall.Kill(pid, 0) == nil {
		_ = syscall.Kill(pid, syscall.SIGKILL)
	}
}

func cleanupLockArtifacts() {
	data, err := os.ReadFile(launcherPIDFile)
	if err == nil {
		pid, convErr := strconv.Atoi(strings.TrimSpace(string(data)))
		if convErr == nil && pid > 0 && syscall.Kill(pid, 0) == nil {
			return
		}
	}
	_ = os.Remove(launcherPIDFile)
	_ = os.Remove(launcherLock)
}

func resolvePort(envKey, fallback string) string {
	v := strings.TrimSpace(os.Getenv(envKey))
	if v == "" {
		return fallback
	}
	if v == "0" {
		return randomFreePort()
	}
	return v
}

func randomFreePort() string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "0"
	}
	defer ln.Close()
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	return port
}

func getEnv(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

func isPrebuiltMode() bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv("LAUNCHER_PREBUILT")))
	return v == "1" || v == "true" || v == "yes" || v == "on"
}

func shouldStartNATS() bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv("LAUNCHER_SKIP_NATS")))
	return !(v == "1" || v == "true" || v == "yes" || v == "on")
}

func loadPluginEnv(name string) map[string]string {
	files := findPluginEnvFiles(name)
	out := make(map[string]string)
	for _, f := range files {
		vals, err := parseDotEnvFile(f)
		if err != nil {
			continue
		}
		for k, v := range vals {
			out[k] = v
		}
	}
	return out
}

func findPluginEnvFiles(name string) []string {
	configRoot := strings.TrimSpace(os.Getenv("LAUNCHER_PLUGIN_CONFIG_ROOT"))
	if configRoot == "" {
		configRoot = filepath.Join("config", "plugins")
	}

	roots := []string{
		filepath.Join("plugins", name),
		filepath.Join(configRoot, name),
	}
	out := make([]string, 0, 4)
	seen := map[string]struct{}{}
	addIfExists := func(path string) {
		if _, exists := seen[path]; exists {
			return
		}
		if _, err := os.Stat(path); err == nil {
			out = append(out, path)
			seen[path] = struct{}{}
		}
	}
	for _, root := range roots {
		addIfExists(filepath.Join(root, ".env"))
		addIfExists(filepath.Join(root, ".env.local"))
	}
	return out
}

func parseDotEnvFile(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	out := make(map[string]string)
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "export ") {
			line = strings.TrimSpace(strings.TrimPrefix(line, "export "))
		}
		i := strings.Index(line, "=")
		if i <= 0 {
			continue
		}
		key := strings.TrimSpace(line[:i])
		val := strings.TrimSpace(line[i+1:])
		val = strings.Trim(val, `"'`)
		if key == "" {
			continue
		}
		out[key] = val
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func mergedEnv(base []string, pluginEnv map[string]string, runtimeEnv map[string]string) []string {
	envMap := make(map[string]string)
	for _, kv := range base {
		if i := strings.Index(kv, "="); i > 0 {
			envMap[kv[:i]] = kv[i+1:]
		}
	}

	// Process env stays highest precedence over plugin files.
	for k, v := range pluginEnv {
		if _, exists := envMap[k]; !exists {
			envMap[k] = v
		}
	}

	// Runtime env always wins.
	for k, v := range runtimeEnv {
		envMap[k] = v
	}

	out := make([]string, 0, len(envMap))
	for k, v := range envMap {
		out = append(out, k+"="+v)
	}
	return out
}
