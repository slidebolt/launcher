// stubborn_plugin ignores SIGTERM to test force-kill behaviour.
package main

import (
	"fmt"
	"os/signal"
	"syscall"
)

func main() {
	fmt.Println("stubborn_plugin started - ignoring SIGTERM")
	signal.Ignore(syscall.SIGTERM)
	select {} // run forever until SIGKILL
}
