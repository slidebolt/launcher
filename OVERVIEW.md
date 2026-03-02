### `launcher` repository

#### Project Overview

This repository contains the `launcher` for the Slidebolt system. It is a command-line application responsible for starting, stopping, and supervising the entire Slidebolt ecosystem, including the gateway and all plugins.

#### Architecture

The `launcher` is a Go application that acts as a process manager. It can operate in two modes:

1.  **Source Mode**: In this mode, the launcher discovers and builds the gateway and plugins from their source code.
2.  **Prebuilt Mode**: In this mode, the launcher uses pre-compiled binaries.

The launcher is responsible for:

-   Ensuring only one instance of the launcher is running at a time.
-   Setting up the necessary directory structure for binaries, logs, PIDs, and data.
-   Starting and managing a NATS server, which serves as the message bus for the system.
-   Starting and supervising the gateway and all discovered plugins. If a plugin crashes, the launcher will automatically restart it.
-   Gracefully shutting down all services when it receives a termination signal.

#### Key Files

| File | Description |
| :--- | :--- |
| `go.mod` | Defines the Go module and its dependency on the `slidebolt/sdk-runner`. |
| `main.go` | Contains the complete logic for the launcher, including service management, build processes, plugin discovery, and process supervision. |

#### Available Commands

The launcher is controlled via command-line arguments:

| Command | Description |
| :--- | :--- |
| `launcher up` | Starts all Slidebolt services, including NATS, the gateway, and all plugins. It will then continue to run and supervise the processes. |
| `launcher down` | Stops all running services and cleans up any lock files and PID files. |
| `launcher status`| Displays the status of all running services, including their process IDs (PIDs). |
