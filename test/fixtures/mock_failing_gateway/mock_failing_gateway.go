// Mock failing gateway - never responds to health checks
package main

import (
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

	// Always return 500 on health endpoint
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"status":"error"}`))
	})

	addr := fmt.Sprintf("%s:%s", host, port)
	fmt.Printf("Mock failing gateway starting on %s (will always fail health checks)\n", addr)

	server := &http.Server{Addr: addr, Handler: mux}
	go server.ListenAndServe()

	// Run forever
	time.Sleep(24 * time.Hour)
}
