// Mock gateway for testing - responds to health checks
package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"
)

func main() {
	port := os.Getenv("LAUNCHER_API_PORT")
	if port == "" {
		port = "8082"
	}
	host := os.Getenv("LAUNCHER_API_HOST")
	if host == "" {
		host = "127.0.0.1"
	}

	// Delay before starting (configurable for testing slow start)
	delay := os.Getenv("MOCK_DELAY_MS")
	if delay != "" {
		if ms, err := time.ParseDuration(delay + "ms"); err == nil {
			time.Sleep(ms)
		}
	}

	mux := http.NewServeMux()

	// Health endpoint
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	})

	// Runtime discovery endpoint
	mux.HandleFunc("/_internal/runtime", func(w http.ResponseWriter, r *http.Request) {
		natsURL := os.Getenv("LAUNCHER_NATS_URL")
		if natsURL == "" {
			natsURL = "nats://127.0.0.1:4224"
		}
		response := map[string]string{
			"nats_url": natsURL,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	})

	addr := fmt.Sprintf("%s:%s", host, port)
	fmt.Printf("Mock gateway starting on %s\n", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to start: %v\n", err)
		os.Exit(1)
	}
}
