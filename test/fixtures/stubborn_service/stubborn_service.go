// Mock stubborn service - ignores SIGTERM to test force kill
package main

import (
	"fmt"
	"os/signal"
	"syscall"
)

func main() {
	fmt.Println("Stubborn service started - ignoring SIGTERM")

	// Ignore SIGTERM
	signal.Ignore(syscall.SIGTERM)

	// Wait forever (or until SIGKILL)
	select {}
}
