package main

import (
	"encoding/json"
	"net/http"
	"time"
)

// WaitUntilHealthy polls url at 200 ms intervals until it gets HTTP 200 or
// timeout elapses. Returns true when healthy.
func WaitUntilHealthy(url string, timeout time.Duration) bool {
	client := http.Client{Timeout: 200 * time.Millisecond}
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		resp, err := client.Get(url)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return true
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	return false
}

// DiscoverRuntime queries the gateway's /_internal/runtime endpoint and
// returns the NATS URL it reports. Returns ("", false) on any failure.
func DiscoverRuntime(apiURL string) (string, bool) {
	client := http.Client{Timeout: 500 * time.Millisecond}
	resp, err := client.Get(apiURL + "/_internal/runtime")
	if err != nil || resp.StatusCode != http.StatusOK {
		if resp != nil {
			resp.Body.Close()
		}
		return "", false
	}
	defer resp.Body.Close()

	var payload struct {
		NATSURL string `json:"nats_url"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil || payload.NATSURL == "" {
		return "", false
	}
	return payload.NATSURL, true
}
