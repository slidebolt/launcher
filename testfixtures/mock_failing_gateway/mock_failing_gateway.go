// mock_failing_gateway binds to the API port but always returns 500 on health checks.
// Used to test launcher behaviour when the gateway never becomes healthy.
package main

import (
	"fmt"
	"net/http"
	"os"
)

func main() {
	port := getenv("LAUNCHER_API_PORT", getenv("API_PORT", "8082"))
	host := getenv("LAUNCHER_API_HOST", getenv("API_HOST", "127.0.0.1"))

	mux := http.NewServeMux()
	mux.HandleFunc("/_internal/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, `{"status":"error"}`)
	})

	addr := fmt.Sprintf("%s:%s", host, port)
	fmt.Printf("mock_failing_gateway listening on %s\n", addr)
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
