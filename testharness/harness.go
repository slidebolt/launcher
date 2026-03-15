package testharness

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// World holds the state for a single Cucumber scenario.
// Each scenario gets its own isolated temp directory and launcher process.
type World struct {
	T       *testing.T
	TempDir string

	proc    *exec.Cmd
	cleanup []func()
	mu      sync.Mutex
}

func NewWorld(t *testing.T) *World {
	t.Helper()
	dir, err := os.MkdirTemp("", "launcher-test-*")
	if err != nil {
		t.Fatalf("create temp dir: %v", err)
	}
	w := &World{T: t, TempDir: dir}
	t.Cleanup(w.Cleanup)
	return w
}

// Cleanup kills the launcher process and removes the temp directory.
func (w *World) Cleanup() {
	w.mu.Lock()
	fns := w.cleanup
	w.mu.Unlock()
	for i := len(fns) - 1; i >= 0; i-- {
		fns[i]()
	}
	os.RemoveAll(w.TempDir)
}

// AddCleanup registers a function to run during Cleanup.
func (w *World) AddCleanup(fn func()) {
	w.mu.Lock()
	w.cleanup = append(w.cleanup, fn)
	w.mu.Unlock()
}

// LauncherBin returns the path to the launcher binary, building it if needed.
// The binary is cached in a package-level sync.Once so it is only built once
// per test run.
func (w *World) LauncherBin() string {
	return LauncherBin(w.T)
}

// --- Fixture cache ---

var (
	launcherOnce sync.Once
	launcherBin  string

	fixtureOnce sync.Once
	fixtureBins map[string]string
)

// LauncherBin builds (once) and returns the launcher binary path.
func LauncherBin(t *testing.T) string {
	t.Helper()
	launcherOnce.Do(func() {
		dir, err := os.MkdirTemp("", "launcher-bin-*")
		if err != nil {
			t.Fatalf("temp dir for launcher: %v", err)
		}
		bin := filepath.Join(dir, "launcher")
		cmd := exec.Command("go", "build", "-o", bin, ".")
		cmd.Dir = repoRoot()
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("build launcher: %v\n%s", err, out)
		}
		launcherBin = bin
	})
	return launcherBin
}

// FixtureBin builds (once) the named fixture and returns its binary path.
// name must match a directory under testfixtures/.
func FixtureBin(t *testing.T, name string) string {
	t.Helper()
	fixtureOnce.Do(func() {
		fixtureBins = make(map[string]string)
		fixturesDir := filepath.Join(repoRoot(), "testfixtures")
		entries, err := os.ReadDir(fixturesDir)
		if err != nil {
			t.Fatalf("read testfixtures: %v", err)
		}
		dir, err := os.MkdirTemp("", "launcher-fixtures-*")
		if err != nil {
			t.Fatalf("temp dir for fixtures: %v", err)
		}
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			srcDir := filepath.Join(fixturesDir, e.Name())
			out := filepath.Join(dir, e.Name())
			cmd := exec.Command("go", "build", "-o", out, ".")
			cmd.Dir = srcDir
			cmd.Env = append(os.Environ(), "GOWORK=off")
			if output, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("build fixture %s: %v\n%s", e.Name(), err, output)
			}
			fixtureBins[e.Name()] = out
		}
	})
	bin, ok := fixtureBins[name]
	if !ok {
		t.Fatalf("unknown fixture: %s", name)
	}
	return bin
}

// --- Prebuilt environment setup ---

// SetupPrebuilt creates .build/bin/, .build/pids/, .build/logs/, .build/data/
// and populates binaries from the provided map (name → src path).
// It also writes a manifest.json listing all binaries.
func SetupPrebuilt(t *testing.T, dir string, binaries map[string]string) {
	t.Helper()
	for _, sub := range []string{".build/bin", ".build/pids", ".build/logs", ".build/data"} {
		if err := os.MkdirAll(filepath.Join(dir, sub), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", sub, err)
		}
	}
	binDir := filepath.Join(dir, ".build/bin")
	for dest, src := range binaries {
		data, err := os.ReadFile(src)
		if err != nil {
			t.Fatalf("read %s: %v", src, err)
		}
		if err := os.WriteFile(filepath.Join(binDir, dest), data, 0o755); err != nil {
			t.Fatalf("write %s: %v", dest, err)
		}
	}

	// manifest.json
	var sb strings.Builder
	sb.WriteString("[\n")
	first := true
	for name := range binaries {
		if !first {
			sb.WriteString(",\n")
		}
		first = false
		id := strings.TrimPrefix(name, "plugin-")
		fmt.Fprintf(&sb, `  {"id": "%s", "binary": "%s"}`, id, name)
	}
	sb.WriteString("\n]\n")
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), []byte(sb.String()), 0o644); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
}

// --- Process helpers ---

// StartLauncher runs the launcher binary with the given args and env overrides,
// working in dir. Returns the started *exec.Cmd (not yet waited on).
// Stdout and Stderr of the launcher are written to w (or discarded if w is nil).
func StartLauncher(t *testing.T, dir string, env map[string]string, out io.Writer, args ...string) *exec.Cmd {
	t.Helper()
	bin := LauncherBin(t)
	cmd := exec.Command(bin, args...)
	cmd.Dir = dir
	// Start with a clean env — strip ambient LAUNCHER_* vars to avoid interference.
	base := filterEnv(os.Environ(), func(k string) bool {
		return !strings.HasPrefix(k, "LAUNCHER_")
	})
	cmd.Env = base
	for k, v := range env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	if out != nil {
		cmd.Stdout = out
		cmd.Stderr = out
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start launcher: %v", err)
	}
	return cmd
}

// filterEnv returns only the env entries for which keep(key) is true.
func filterEnv(env []string, keep func(string) bool) []string {
	out := make([]string, 0, len(env))
	for _, kv := range env {
		key := kv
		if i := strings.Index(kv, "="); i > 0 {
			key = kv[:i]
		}
		if keep(key) {
			out = append(out, kv)
		}
	}
	return out
}

// WaitForFile polls until path exists or timeout elapses.
func WaitForFile(path string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return true
		}
		time.Sleep(20 * time.Millisecond)
	}
	return false
}

// WaitForHealth polls url until HTTP 200 or timeout.
func WaitForHealth(url string, timeout time.Duration) bool {
	client := http.Client{Timeout: 150 * time.Millisecond}
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		resp, err := client.Get(url)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return true
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	return false
}

// FreePort returns a free TCP port on 127.0.0.1 as a string.
func FreePort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("find free port: %v", err)
	}
	defer ln.Close()
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	return port
}

// ReadPID reads a PID file and returns the integer, or 0 on error.
func ReadPID(path string) int {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	pid, _ := strconv.Atoi(strings.TrimSpace(string(data)))
	return pid
}

// IsAlive returns true if the process with pid is running.
func IsAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	p, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	return p.Signal(nil) == nil
}

// StopCmd sends SIGTERM to cmd, waits up to 5 s (enough for launcher's own 2 s
// shutdown grace period), then SIGKILLs if still running.
func StopCmd(cmd *exec.Cmd) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	cmd.Process.Signal(os.Interrupt)
	done := make(chan struct{})
	go func() { cmd.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		cmd.Process.Kill()
		<-done
	}
}

// repoRoot returns the absolute path to the launcher module root by walking
// up from the current working directory until go.mod is found.
func repoRoot() string {
	dir, err := os.Getwd()
	if err != nil {
		panic(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			panic("could not find go.mod from " + dir)
		}
		dir = parent
	}
}
