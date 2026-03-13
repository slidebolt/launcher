// mock_gateway responds to health checks and reports its NATS URL via runtime discovery.
// It is used as a drop-in gateway binary in launcher integration tests.
package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"
)

func main() {
	port := getenv("LAUNCHER_API_PORT", getenv("API_PORT", "8082"))
	host := getenv("LAUNCHER_API_HOST", getenv("API_HOST", "127.0.0.1"))

	if delay := os.Getenv("MOCK_DELAY_MS"); delay != "" {
		if ms, err := time.ParseDuration(delay + "ms"); err == nil {
			time.Sleep(ms)
		}
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/_internal/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"status":"ok"}`)
	})
	mux.HandleFunc("/_internal/runtime", func(w http.ResponseWriter, r *http.Request) {
		natsURL := getenv("NATS_URL", "nats://127.0.0.1:4224")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"nats_url": natsURL})
	})

	addr := fmt.Sprintf("%s:%s", host, port)
	fmt.Printf("mock_gateway listening on %s\n", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
