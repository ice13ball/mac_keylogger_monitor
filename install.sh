#!/bin/bash

# Install SleepWatcher if not already installed
brew list sleepwatcher &>/dev/null || brew install sleepwatcher

# Create hook directories
mkdir -p "$HOME/.sleep" "$HOME/.wakeup"

# Create the main detection script
cat << 'EOF' > "$HOME/detect_suspicious.sh"
#!/bin/bash

LOGFILE="\$HOME/suspicious_items.log"
echo "==== \$(date) ====" > "\$LOGFILE"

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
tccutil reset All
sqlite3 "\$HOME/Library/Application Support/com.apple.TCC/TCC.db" \
"SELECT service,client,auth_value FROM access WHERE service='kTCCServiceListenEvent' OR service='kTCCServiceAccessibility';" >> "\$LOGFILE"

echo "[4] Listing active keyboard-related processes..." >> "\$LOGFILE"
ps aux | grep -Ei "keylog|listen|hid|event|keyboard" >> "\$LOGFILE"

echo "[5] Done. Results saved to \$LOGFILE"

# Extract alerts and notify user
ALERTS=\$(grep -Ei "keylog|monitor|Program|Accessibility" "\$LOGFILE" | head -n 5 | tr '\n' '; ')
osascript -e "display notification \"Suspicious activity found. Log opened.\" with title \"Security Alert\""
open -a TextEdit "\$LOGFILE"
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

echo "Setup complete. The detection script will run after each wakeup and show a notification."