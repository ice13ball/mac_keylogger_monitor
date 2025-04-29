#!/bin/bash

# Install SleepWatcher and SQLite if not already installed
brew list sleepwatcher &>/dev/null || brew install sleepwatcher
brew list sqlite &>/dev/null || brew install sqlite

# Create hook directories
mkdir -p "$HOME/.sleep" "$HOME/.wakeup"

# Create whitelist file if it doesn't exist
WHITELIST_FILE="$HOME/whitelist_items.txt"
touch "$WHITELIST_FILE"

# Create the main detection script
cat << 'EOF' > "$HOME/detect_suspicious.sh"
#!/bin/bash

LOGFILE="\$HOME/suspicious_items.log"
WHITELIST_FILE="\$HOME/whitelist_items.txt"
TEMP_ALERTS="\$HOME/temp_alerts.log"

echo "==== \$(date) ====" > "\$LOGFILE"

check_whitelist() {
  ITEM="\$1"
  while IFS= read -r LINE; do
    if [[ "\$ITEM" == *"\$LINE"* ]]; then
      return 1
    fi
  done < "\$WHITELIST_FILE"
  return 0
}

echo "[1] Checking LaunchAgents and LaunchDaemons..." >> "\$LOGFILE"
for DIR in /Library/LaunchAgents /Library/LaunchDaemons "\$HOME/Library/LaunchAgents"; do
  if [ -d "\$DIR" ]; then
    echo ">> \$DIR" >> "\$LOGFILE"
    find "\$DIR" -type f -name "*.plist" -exec sh -c '
      for file do
        echo "--- \$file ---"
        plutil -p "\$file" 2>/dev/null | grep -Ei "RunAtLoad|Program|Label"
      done
    ' sh {} + >> "\$LOGFILE"
  fi
done

echo "[2] Searching for potential keylog or monitor files..." >> "\$LOGFILE"
if command -v sudo &>/dev/null; then
  sudo find / -type f \( -iname "*keylog*" -o -iname "*monitor*" \) 2>/dev/null >> "\$LOGFILE"
else
  find / -type f \( -iname "*keylog*" -o -iname "*monitor*" \) 2>/dev/null >> "\$LOGFILE"
fi

echo "[3] Checking apps with Input Monitoring or Accessibility access..." >> "\$LOGFILE"
if [ -f "\$HOME/Library/Application Support/com.apple.TCC/TCC.db" ]; then
  sqlite3 "\$HOME/Library/Application Support/com.apple.TCC/TCC.db" \
  "SELECT service,client,auth_value FROM access WHERE service='kTCCServiceListenEvent' OR service='kTCCServiceAccessibility';" >> "\$LOGFILE"
else
  echo "TCC.db not found. Skipping accessibility check." >> "\$LOGFILE"
fi

echo "[4] Listing active keyboard-related processes..." >> "\$LOGFILE"
ps aux | grep -Ei "keylog|listen|hid|event|keyboard" >> "\$LOGFILE"

echo "[5] Done. Results saved to \$LOGFILE"

# Extract alerts, check against whitelist, and notify user
> "\$TEMP_ALERTS"
while IFS= read -r LINE; do
  if echo "\$LINE" | grep -Ei "keylog|monitor|Program|Accessibility" >/dev/null; then
    if check_whitelist "\$LINE"; then
      echo "\$LINE" >> "\$TEMP_ALERTS"
    fi
  fi
done < "\$LOGFILE"

if [ -s "\$TEMP_ALERTS" ]; then
  ALERTS=\$(cat "\$TEMP_ALERTS" | head -n 5 | tr '\n' '; ')
  osascript -e "display notification \"Suspicious activity detected.\" with title \"Security Alert\" subtitle \"\$ALERTS\""
  open -a TextEdit "\$LOGFILE"
fi

rm -f "\$TEMP_ALERTS"
EOF

chmod +x "$HOME/detect_suspicious.sh"

# Create the wakeup hook script
cat << EOF > "$HOME/.wakeup/detect.sh"
#!/bin/bash
\$HOME/detect_suspicious.sh
EOF

chmod +x "$HOME/.wakeup/detect.sh"

# Start SleepWatcher as a user service
brew services restart sleepwatcher

echo "Setup complete. Detection script will run after each wakeup, show notification, and use whitelist filtering."