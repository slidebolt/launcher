package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// ServiceStatus describes the observed state of a managed service.
type ServiceStatus struct {
	Name    string
	PID     int
	Alive   bool
	Restart bool
}

// ManagedService is a single supervised process entry.
type ManagedService struct {
	Name    string
	Binary  string
	Args    []string // optional additional arguments passed to Binary
	Env     []string
	Restart bool // if true, restart on unexpected exit with exponential back-off

	mu   sync.Mutex
	cmd  *exec.Cmd
	stop chan struct{} // close to request supervision stop
}

// pid returns the current process ID, or 0 if not running.
func (svc *ManagedService) pid() int {
	svc.mu.Lock()
	defer svc.mu.Unlock()
	if svc.cmd != nil && svc.cmd.Process != nil {
		return svc.cmd.Process.Pid
	}
	return 0
}

// Supervisor manages a set of named processes. It owns all process state
// in memory; PID files are written for cross-process queries (status/down)
// but are never used for control flow within a running supervisor.
type Supervisor struct {
	cfg      Config
	services map[string]*ManagedService
	wg       sync.WaitGroup
	mu       sync.RWMutex
}

func NewSupervisor(cfg Config) *Supervisor {
	return &Supervisor{
		cfg:      cfg,
		services: make(map[string]*ManagedService),
	}
}

// Start launches svc. If svc.Restart is true, a supervision goroutine manages
// restarts with exponential back-off. For one-shot services (Restart: false)
// the process is started and control returns immediately.
func (s *Supervisor) Start(svc *ManagedService) error {
	svc.stop = make(chan struct{})

	s.mu.Lock()
	s.services[svc.Name] = svc
	s.mu.Unlock()

	if svc.Restart {
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.supervise(svc)
		}()
		return nil
	}

	// One-shot: launch once, reap asynchronously so ProcessState gets populated.
	cmd, err := s.launch(svc)
	if err != nil {
		return err
	}
	svc.mu.Lock()
	svc.cmd = cmd
	svc.mu.Unlock()
	go cmd.Wait() // populate ProcessState when the process exits
	return nil
}

// StopAll signals all supervised loops to exit, then SIGTERMs every running
// process. After a 2 s grace period, stragglers are SIGKILLed. Blocks until
// all supervised goroutines have exited.
func (s *Supervisor) StopAll() {
	s.mu.RLock()
	svcs := make([]*ManagedService, 0, len(s.services))
	for _, svc := range s.services {
		svcs = append(svcs, svc)
	}
	s.mu.RUnlock()

	// Close stop channels so supervision goroutines don't restart after kill.
	for _, svc := range svcs {
		if svc.stop != nil {
			select {
			case <-svc.stop:
			default:
				close(svc.stop)
			}
		}
	}

	// SIGTERM every live process.
	type pidEntry struct {
		svc *ManagedService
		pid int
	}
	var entries []pidEntry
	for _, svc := range svcs {
		svc.mu.Lock()
		cmd := svc.cmd
		svc.mu.Unlock()
		if cmd != nil && cmd.Process != nil {
			pid := cmd.Process.Pid
			entries = append(entries, pidEntry{svc, pid})
			cmd.Process.Signal(syscall.SIGTERM)
		}
	}

	// Wait up to 2 s per process, then SIGKILL stragglers.
	deadline := time.Now().Add(2 * time.Second)
	for _, e := range entries {
		for time.Now().Before(deadline) {
			if syscall.Kill(e.pid, 0) != nil {
				break // process is gone
			}
			time.Sleep(50 * time.Millisecond)
		}
		if syscall.Kill(e.pid, 0) == nil {
			syscall.Kill(e.pid, syscall.SIGKILL)
		}
		s.removePID(e.svc.Name)
	}

	s.wg.Wait()
}

// Status returns the observed state of every service tracked by PID files.
// It checks process liveness via kill(pid, 0) so stale files show as dead.
func (s *Supervisor) Status() []ServiceStatus {
	files, _ := filepath.Glob(filepath.Join(s.cfg.PIDDir, "*.pid"))
	out := make([]ServiceStatus, 0, len(files))
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
		if err != nil {
			continue
		}
		name := strings.TrimSuffix(filepath.Base(f), ".pid")
		alive := syscall.Kill(pid, 0) == nil
		s.mu.RLock()
		svc := s.services[name]
		s.mu.RUnlock()
		restart := svc != nil && svc.Restart
		out = append(out, ServiceStatus{
			Name:    name,
			PID:     pid,
			Alive:   alive,
			Restart: restart,
		})
	}
	return out
}

// supervise runs svc in a restart loop with exponential back-off (200 ms → 5 s).
// Back-off resets after the service runs stably for ≥ 30 s. Exits when svc.stop
// is closed.
func (s *Supervisor) supervise(svc *ManagedService) {
	const (
		initialBackoff  = 200 * time.Millisecond
		maxBackoff      = 5 * time.Second
		stableThreshold = 30 * time.Second
	)
	backoff := initialBackoff

	for {
		select {
		case <-svc.stop:
			return
		default:
		}

		started := time.Now()
		cmd, err := s.launch(svc)
		if err != nil {
			logger.Error("service launch failed", "name", svc.Name, "error", err)
			return // binary missing or not executable — no point retrying
		}

		svc.mu.Lock()
		svc.cmd = cmd
		svc.mu.Unlock()

		cmd.Wait()
		logger.Info("service exited", "name", svc.Name, "exit_code", exitCode(cmd), "elapsed_ms", time.Since(started).Milliseconds())

		select {
		case <-svc.stop:
			s.removePID(svc.Name)
			return
		default:
		}

		if time.Since(started) >= stableThreshold {
			backoff = initialBackoff // stable run — reset back-off
		}

		logger.Info("restarting service", "name", svc.Name, "backoff", backoff)

		select {
		case <-svc.stop:
			s.removePID(svc.Name)
			return
		case <-time.After(backoff):
		}

		backoff *= 2
		if backoff > maxBackoff {
			backoff = maxBackoff
		}
	}
}

// launch starts the binary for svc, wires up log output, and writes the PID
// file. The caller is responsible for waiting on the returned cmd.
func (s *Supervisor) launch(svc *ManagedService) (*exec.Cmd, error) {
	logger.Debug("launching service", "name", svc.Name, "binary", svc.Binary)
	os.MkdirAll(filepath.Join(s.cfg.DataDir, svc.Name), 0o755)

	logPath := filepath.Join(s.cfg.LogDir, svc.Name+".log")
	logFile, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, fmt.Errorf("open log %s: %w", logPath, err)
	}
	defer logFile.Close()

	cmd := exec.Command(svc.Binary, svc.Args...)
	cmd.Env = svc.Env
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGTERM}

	if err := cmd.Start(); err != nil {
		return nil, err
	}

	s.writePID(svc.Name, cmd.Process.Pid)
	return cmd, nil
}

func (s *Supervisor) writePID(name string, pid int) {
	os.WriteFile(filepath.Join(s.cfg.PIDDir, name+".pid"), []byte(strconv.Itoa(pid)), 0o644)
}

func (s *Supervisor) removePID(name string) {
	os.Remove(filepath.Join(s.cfg.PIDDir, name+".pid"))
}

func exitCode(cmd *exec.Cmd) int {
	if cmd.ProcessState != nil {
		return cmd.ProcessState.ExitCode()
	}
	return -1
}
