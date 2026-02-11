#!/bin/bash

#########################################################################################
# Set your variables
CONFIG_PASS="configpassword"
PID_FILE=".irchub.pid"

# CONFIG_PASS is the config encryption password
# PID_FILE must match hub.h #define HUB_PID_FILE
#########################################################################################

# Navigate to the hub's directory
cd "$(dirname "$0")"

# Check if the PID file exists
if [ -e "$PID_FILE" ]; then
    # If the PID file exists, check if the process is still running
    PID=$(cat "$PID_FILE")
    if ps -p "$PID" > /dev/null 2>&1; then
        echo "Hub is already running (PID: $PID). Exiting."
        exit 1
    else
        # The process is not running, but the PID file was left behind. Remove it.
        echo "Found stale PID file. Removing."
        rm -f "$PID_FILE"
    fi
fi

# Run the hub
./irchub "$CONFIG_PASS" &

echo "Hub started (PID: $!)"
