# Launcher Commands

The `launcher` is a process manager for the Slidebolt system. It handles building (in source mode), starting, and supervising all services.

| Command | Description |
| :--- | :--- |
| `launcher up` | Starts the entire Slidebolt stack (NATS, Gateway, and all Plugins). The process stays in the foreground to supervise and auto-restart services. |
| `launcher down` | Gracefully stops all running Slidebolt services and cleans up PID/lock files. |
| `launcher status` | Shows the current status and PIDs of all managed services. |

## Mode Selection

The launcher's behavior can be modified by environment variables:

- **Source Mode (Default)**: Launcher discovers plugins in the `plugins/` directory and builds them from source before starting.
- **Prebuilt Mode**: If `LAUNCHER_PREBUILT=1` is set, it skips building and looks for pre-compiled binaries in `.build/bin/`.
