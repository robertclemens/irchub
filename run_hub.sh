#!/bin/bash

#########################################################################################
# Set your variables
export HUB_PASS="configpasswordhere"
PID_FILE=".irchub.pid"

# HUB_PASS is the config encryption password (read by irchub via getenv)
# PID_FILE must match hub.h #define HUB_PID_FILE
#########################################################################################

# Navigate to the hub's directory
cd "$(dirname "$0")"

# Check if the PID file exists
if [ -e "$PID_FILE" ]; then
    PID=$(cat "$PID_FILE")
    if ps -p "$PID" > /dev/null 2>&1; then
        echo "Hub is already running (PID: $PID). Exiting."
        exit 1
    else
        echo "Found stale PID file. Removing."
        rm -f "$PID_FILE"
    fi
fi

./irchub &

echo "Hub started (PID: $!)"
