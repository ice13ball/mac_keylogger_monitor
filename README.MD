# Suspicious Activity Detector (macOS)

This script sets up an automated security check that runs **after each wake-up** (e.g., unlocking or resuming from sleep). It checks for:

- Suspicious `.plist` files in `LaunchAgents`/`LaunchDaemons`
- Files suggesting keyloggers or monitoring tools
- Apps with Input Monitoring or Accessibility access
- Keyboard-related running processes
- Sends macOS **notifications** if suspicious items are found
- Uses a **whitelist file** to ignore known safe entries

## Requirements

- macOS
- [Homebrew](https://brew.sh) installed
- Admin password for full scan (some features use `sudo`)
- SleepWatcher (`brew install sleepwatcher`) – installed automatically
- SQLite (`brew install sqlite`) – installed automatically

## Whitelist

You can create a `whitelist_items.txt` file in your home directory to suppress alerts from known safe apps, processes, or paths.  
Each line should contain a unique keyword or partial path to ignore.

**Example**:

```text
com.google.keystone
/Library/LaunchAgents/com.adobe.*
GoogleSoftwareUpdate
```

## Installation

Run the script provided in `install.sh`. It will:

- Install required tools
- Create wake-from-sleep hooks
- Set up the detection script
- Start monitoring automatically

Alerts will appear as native macOS notifications and open logs in TextEdit.
