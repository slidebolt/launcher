package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/slidebolt/sdk-runner"
)

const (
	buildDir = ".build"
	binDir   = ".build/bin"
	logDir   = ".build/logs"
	pidDir   = ".build/pids"
	dataDir  = ".build/data"
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
	setupDirs()

	fmt.Println("1. Infrastructure: Starting NATS...")
	startNATS()

	fmt.Println("2. Gateway: Building and starting...")
	build("gateway", "gateway")
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
		down()
		os.Exit(1)
	}
	fmt.Println("Gateway verified: PERFECT.")

	if discovered, ok := discoverRuntime(); ok {
		cfg.NATSURL = discovered.NATSURL
		fmt.Printf("Runtime discovered: nats=%s\n", cfg.NATSURL)
	}

	fmt.Println("3. Plugins: Building and supervising...")
	for _, path := range discoverPluginPaths("plugins") {
		name := filepath.Base(path)
		build(name, path)
		go supervise(name, filepath.Join(binDir, name))
	}

	fmt.Println("\nGateway is up. Supervision active.")
	select {}
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
		cmd := startService(name, bin, map[string]string{
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

func setupDirs() {
	os.RemoveAll(buildDir)
	for _, d := range []string{binDir, logDir, pidDir, dataDir} {
		os.MkdirAll(d, 0o755)
	}
}

func discoverPluginPaths(root string) []string {
	entries, _ := os.ReadDir(root)
	var paths []string
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		name := entry.Name()
		if strings.HasPrefix(name, ".") || strings.HasSuffix(name, ".del") {
			continue
		}
		path := filepath.Join(root, name)
		if isBuildable(path) {
			paths = append(paths, path)
		}
	}
	return paths
}

func isBuildable(path string) bool {
	_, errMod := os.Stat(filepath.Join(path, "go.mod"))
	_, errMain := os.Stat(filepath.Join(path, "main.go"))
	return errMod == nil && errMain == nil
}

func build(name, path string) {
	out := filepath.Join(binDir, name)
	cmd := exec.Command("go", "build", "-o", out, "./"+path)
	if out, err := cmd.CombinedOutput(); err != nil {
		fmt.Printf("build error [%s]: %s\n", name, string(out))
		os.Exit(1)
	}
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
	if err := cmd.Start(); err == nil {
		savePID("nats", cmd.Process.Pid)
	}
}

func startService(name, bin string, env map[string]string) *exec.Cmd {
	os.MkdirAll(filepath.Join(dataDir, name), 0o755)
	logFile, _ := os.OpenFile(filepath.Join(logDir, name+".log"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)

	cmd := exec.Command(bin)
	cmd.Env = append(os.Environ()[:len(os.Environ()):len(os.Environ())], envSlice(env)...)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	if err := cmd.Start(); err != nil {
		return nil
	}
	savePID(name, cmd.Process.Pid)
	return cmd
}

func down() {
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
	fmt.Println("All services stopped.")
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
