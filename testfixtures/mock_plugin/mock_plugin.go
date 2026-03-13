// mock_plugin logs its env, then runs until SIGTERM.
// MOCK_PLUGIN_EXIT_MS=N causes it to self-exit after N milliseconds (tests crash recovery).
package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	fmt.Println("mock_plugin started")
	for _, kv := range os.Environ() {
		fmt.Println(kv)
	}

	if delay := os.Getenv("MOCK_PLUGIN_EXIT_MS"); delay != "" {
		if ms, err := time.ParseDuration(delay + "ms"); err == nil {
			go func() {
				time.Sleep(ms)
				fmt.Println("mock_plugin self-exiting")
				os.Exit(0)
			}()
		}
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	<-sigCh
	fmt.Println("mock_plugin received shutdown signal")
}
