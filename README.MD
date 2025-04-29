# Suspicious Activity Detector (macOS)

This script sets up an automated security check that runs **after each wake-up** (e.g., unlocking or resuming from sleep). It checks for:

- Suspicious `.plist` files in `LaunchAgents`/`LaunchDaemons`
- Files suggesting keyloggers or monitoring tools
- Apps with Input Monitoring or Accessibility access
- Keyboard-related running processes

## Requirements

- macOS
- [Homebrew](https://brew.sh) installed
- Admin password for full scan (some features use `sudo`)
- SleepWatcher (`brew install sleepwatcher` – handled by the script)

