package main

import (
	"fmt"
	"os"
)

func main() {
	initLogger()

	if len(os.Args) < 2 {
		fmt.Println(ui.Title("Launcher"))
		fmt.Println("Usage: launcher [up|down|status]")
		os.Exit(1)
	}

	cfg := LoadConfig()

	switch os.Args[1] {
	case "up":
		cmdUp(cfg)
	case "down":
		cmdDown(cfg)
	case "status":
		cmdStatus(cfg)
	default:
		logger.Error("unknown command", "command", os.Args[1])
		os.Exit(1)
	}
}
