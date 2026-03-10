// Mock plugin for testing - logs env vars, exits after configurable duration
package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	// Log all LAUNCHER_ and plugin-specific env vars
	for _, env := range os.Environ() {
		fmt.Println(env)
	}

	// Get exit delay (0 = run forever until signaled)
	exitDelay := os.Getenv("MOCK_PLUGIN_EXIT_MS")
	if exitDelay != "" {
		if ms, err := time.ParseDuration(exitDelay + "ms"); err == nil {
			go func() {
				time.Sleep(ms)
				fmt.Println("Mock plugin exiting after delay")
				os.Exit(0)
			}()
		}
	}

	// Wait for SIGTERM/SIGINT
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	<-sigCh
	fmt.Println("Mock plugin received shutdown signal")
}
