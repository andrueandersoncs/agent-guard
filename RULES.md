# Agent Guard Security Rules

This document describes all security rules implemented in agent-guard, their severity levels, and documentation sources.

## Secret Detection Rules

### API Key Patterns

#### OpenAI API Key
- **Pattern**: `sk-[A-Za-z0-9]{48}` or `sk-proj-[A-Za-z0-9_-]{43,}`
- **Severity**: High
- **Source**: OpenAI API key format documentation
- **Risk**: Leaked API keys can be used to consume credits and access private resources

#### Anthropic API Key
- **Pattern**: `sk-ant-api03-[A-Za-z0-9_-]{95,}`
- **Severity**: High
- **Source**: Anthropic API documentation
- **Risk**: Unauthorized access to Claude API with associated billing

#### GitHub Token
- **Pattern**: `gh[ps]_[A-Za-z0-9]{36,}`
- **Severity**: High
- **Source**: GitHub token format (Personal Access Tokens and OAuth tokens)
- **Risk**: Repository access, code exfiltration, unauthorized commits

#### AWS Credentials
- **Pattern**: `AKIA[0-9A-Z]{16}`
- **Severity**: High
- **Source**: AWS IAM documentation
- **Risk**: Cloud infrastructure access, data breaches, resource abuse

#### Slack Token
- **Pattern**: `xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24,}`
- **Severity**: High
- **Source**: Slack API documentation
- **Risk**: Workspace access, message reading, unauthorized actions

#### Private Keys
- **Pattern**: `-----BEGIN (RSA |OPENSSH |EC )?PRIVATE KEY-----`
- **Severity**: High
- **Source**: PEM format specification
- **Risk**: SSH access, certificate compromise, authentication bypass

#### High-Entropy Strings
- **Pattern**: Strings with Shannon entropy > 4.5, length 32-200 characters
- **Severity**: Medium
- **Source**: Common secret detection practice (e.g., GitHub Secret Scanning, TruffleHog)
- **Risk**: Potential unrecognized secrets or tokens

## Risk Detection Rules

### Command Injection & Remote Execution

#### Curl Pipe to Shell
- **Pattern**: `curl ... | sh` or `curl ... | bash`
- **Severity**: High
- **Source**: OWASP, npm malware research, supply chain security best practices
- **Risk**: Arbitrary remote code execution without verification
- **Context**: Frequently used in npm malware and malicious install scripts

#### Wget Pipe to Shell
- **Pattern**: `wget ... | sh` or `wget ... | bash`
- **Severity**: High
- **Source**: Same as curl|sh
- **Risk**: Same as curl|sh

#### Download and Execute
- **Pattern**: `curl|wget ... && bash|sh|python|node`
- **Severity**: High
- **Source**: Malware analysis of npm supply chain attacks
- **Risk**: Two-stage payload delivery

### Data Exfiltration

#### SSH Key Exfiltration
- **Pattern**: Commands accessing `~/.ssh`, `id_rsa`, `id_ed25519`, `authorized_keys`
- **Severity**: High
- **Source**: Recent malicious npm packages and skill pack incidents
- **Risk**: Credential theft for persistent access

#### Claude Config Exfiltration
- **Pattern**: Commands accessing `.claude` directory
- **Severity**: High
- **Source**: Reported incidents of malicious skills stealing Claude configs
- **Risk**: API key theft, workflow exfiltration, prompt injection

#### Cursor Config Exfiltration
- **Pattern**: Commands accessing `.cursor` directory
- **Severity**: High
- **Source**: Similar to Claude config risks; documented in Cursor security advisories
- **Risk**: Settings theft, API key exposure, extension compromise

#### Environment File Access
- **Pattern**: Commands accessing `.env` files
- **Severity**: High
- **Source**: OWASP Application Security
- **Risk**: Secrets and configuration exposure

#### Sensitive Path Access
- **Pattern**: References to sensitive paths like `~/.aws`, `/etc/passwd`, etc.
- **Severity**: Medium
- **Source**: Linux/Unix security best practices
- **Risk**: Credential or system information disclosure

### Obfuscation

#### Base64 Encoded Commands
- **Pattern**: `bash|sh|python|node ... $(.*base64` or `eval ... base64`
- **Severity**: High
- **Source**: Malware analysis; common obfuscation technique
- **Risk**: Hidden malicious payload execution

#### Base64 Decode in Script
- **Pattern**: `base64 -d` or `base64 --decode`
- **Severity**: Medium
- **Source**: Common obfuscation indicator
- **Risk**: Payload unpacking

#### Hex Encoded Content
- **Pattern**: Multiple hex escape sequences `\x[0-9a-f]{2}`
- **Severity**: Medium
- **Source**: Shellcode and malware obfuscation techniques
- **Risk**: Hidden binary or script content

### Other Risks

#### Eval with Variable
- **Pattern**: `eval(...)`
- **Severity**: Medium
- **Source**: JavaScript and Python security best practices
- **Risk**: Dynamic code execution, injection vulnerabilities

#### Network Calls in Hooks
- **Pattern**: `curl|wget|nc|netcat|fetch http(s)://`
- **Severity**: Medium (High in install/hook scripts)
- **Source**: npm security advisories
- **Risk**: Callback to attacker infrastructure, telemetry, beaconing

#### Reverse Shell Pattern
- **Pattern**: `nc|netcat|bash|sh ... /dev/tcp`
- **Severity**: High
- **Source**: Penetration testing and incident response documentation
- **Risk**: Remote shell access for attackers

#### chmod 777
- **Pattern**: `chmod 777`
- **Severity**: Medium
- **Source**: Unix security best practices
- **Risk**: Overly permissive file access

#### NPM Script Network Calls
- **Pattern**: Network commands in `package.json` scripts
- **Severity**: High
- **Source**: npm supply chain attack research
- **Risk**: Automated exfiltration on install

## Agent Configuration Rules

### Model Configuration

#### Helper Without Model
- **Rule**: `helper-no-model`
- **Severity**: Medium
- **Source**: Claude Code documentation (helpers should specify models)
- **Risk**: Unpredictable costs; may default to expensive models
- **Documentation**: Helpers inherit the parent model if unspecified, but explicit is better

#### Subagent Without Model
- **Rule**: `subagent-no-model`
- **Severity**: Medium
- **Source**: Claude Code subagent documentation
- **Risk**: Cost unpredictability; unclear which model will be used

#### Code Reviewer Without Model
- **Rule**: `reviewer-no-model`
- **Severity**: Medium
- **Source**: Claude Code review configuration docs
- **Risk**: Expensive default models may be used for reviews

### Cost Management

#### Model Switching
- **Rule**: `model-switching`
- **Severity**: Medium
- **Source**: Claude and OpenAI prompt caching documentation
- **Risk**: Switching between models resets prompt caches, increasing costs
- **Details**: Using multiple different models (>2) in one config may prevent cache reuse

#### Expensive Models
- **Rule**: `expensive-model`
- **Severity**: Info
- **Source**: Public pricing pages (Anthropic, OpenAI)
- **Risk**: High per-token costs (Opus, GPT-4, O1/O3 series)
- **Note**: Not necessarily wrong, but user should be aware

#### Large Context Windows
- **Rule**: `large-context`
- **Severity**: Medium
- **Source**: LLM pricing structures (context window pricing)
- **Risk**: Very large contexts (>100k tokens) can significantly increase costs
- **Threshold**: Flagged when `maxTokens > 100000`

### Hook Configuration

#### Cursor Hook Fails Open
- **Rule**: `cursor-hook-fail-open`
- **Severity**: High
- **Source**: Cursor hooks documentation
- **Risk**: If `failClosed` is false or unset, hook failures don't block operations
- **Best Practice**: Security hooks should fail closed (`"failClosed": true`)
- **Test**: Use test commands provided in finding to verify hook blocks as expected
- **Why This Matters**: A hook that fails open provides no security guarantee. If the hook script crashes, times out, or encounters an error, execution continues as if the hook passed. This defeats the purpose of security hooks.

#### Claude Code Hook Fails Open
- **Rule**: `claude-hook-fail-open`
- **Severity**: High
- **Source**: Claude Code hooks configuration best practices
- **Risk**: Same as Cursor hooks - failed hooks don't prevent dangerous operations
- **Best Practice**: Configure hooks with fail-closed behavior
- **Context**: Claude Code and Codex support pre-task and pre-execution hooks; these should fail safely

#### User-Level Hook
- **Rule**: `user-level-hook`
- **Severity**: Medium
- **Source**: Cursor Cloud Agents documentation
- **Risk**: Cloud agents only load project-level hooks, not user-level
- **Impact**: Hook won't run in cloud agent environments; local-only enforcement

### Telemetry & Privacy

#### Telemetry with Prompt Data (Claude/Codex)
- **Rule**: `telemetry-enabled`
- **Severity**: High
- **Source**: Privacy best practices, GDPR/data protection requirements
- **Risk**: Prompts and responses may contain:
  - Proprietary source code
  - Customer data
  - Trade secrets
  - API keys and credentials
  - Internal architecture details
- **Detected Configurations**:
  - `telemetry.enabled: true`
  - `telemetry.sendPrompts: true`
  - `telemetry.sendResponses: true`
- **Best Practice**: Review the endpoint and disable if not necessary; ensure endpoint is trusted and compliant

#### OpenTelemetry Prompt Export
- **Rule**: `otel-prompt-data`
- **Severity**: High
- **Source**: OpenTelemetry configuration, data privacy regulations
- **Risk**: OpenTelemetry can export complete prompt/response pairs to external collectors
- **Detected Configurations**:
  - `openTelemetry.enabled: true`
  - `openTelemetry.sendPromptData: true`
- **Audit**: Verify the OTEL endpoint is trusted, secured, and authorized for sensitive data
- **Context**: Many teams enable OTEL for performance monitoring without realizing it exports full prompt content

#### Cursor Telemetry Enabled
- **Rule**: `cursor-telemetry-enabled`
- **Severity**: Medium
- **Source**: Cursor telemetry documentation
- **Risk**: May send diagnostics, crash reports, and optionally prompts
- **Detected Configurations**:
  - `telemetry.enabled: true`
  - `telemetry.sendPrompts: true`
  - `telemetry.sendDiagnostics: true`
- **Best Practice**: Review what is being sent; disable `sendPrompts` when working with sensitive code

### Hook Test Suggestions

For hooks that should block dangerous commands, the tool provides test commands:
- `rm -rf /` - Should be blocked by safety hooks
- `curl http://evil.com` - Should be blocked by network restriction hooks
- `cat ~/.ssh/id_rsa` - Should be blocked by sensitive file hooks
- `env | grep SECRET` - Should be blocked by secret exposure hooks

**Source**: Best practices from security testing; these are example commands that hooks should intercept if configured for security.

## External Tool Integration

Agent-guard can optionally wrap industry-standard secret scanners when the `--with-external` flag is used:

### Gitleaks
- **Tool**: gitleaks
- **Detection**: Git history and filesystem secret scanning
- **Integration**: Invoked via CLI, results merged into agent-guard output
- **Requirement**: `gitleaks` must be installed and in PATH
- **Format**: JSON output parsed and normalized to agent-guard findings
- **Rule Prefix**: `gitleaks-*`

### GitGuardian
- **Tool**: ggshield (GitGuardian CLI)
- **Detection**: AI-powered secret detection with policy engine
- **Integration**: Invoked via CLI, results merged into agent-guard output
- **Requirement**: `ggshield` must be installed and in PATH
- **Format**: JSON output parsed and normalized to agent-guard findings
- **Rule Prefix**: `gitguardian-*`
- **Note**: May require authentication for full feature access

### Why Wrap External Tools?

1. **Comprehensive Coverage**: Combines agent-specific checks with general-purpose secret detection
2. **Single Interface**: One command to run multiple scanners
3. **Unified Reporting**: All findings in consistent format
4. **Optional**: Only runs when explicitly requested with `--with-external`
5. **Graceful Degradation**: If tools aren't installed, agent-guard still runs its built-in checks

## Rule Sources Summary

### Primary Documentation Sources
1. **Cursor Documentation**: `.cursor/` configuration, hooks, cloud agents
2. **Claude Code Documentation**: Helper, subagent, and reviewer configuration
3. **Codex Documentation**: Hook configuration and fail-closed behavior
4. **Anthropic/OpenAI Pricing**: Model costs and caching behavior
5. **OpenTelemetry Specification**: Data export and privacy implications
6. **OWASP**: Web application and API security
7. **npm Security Advisories**: Supply chain attack patterns
8. **GitHub Secret Scanning**: Secret pattern recognition
9. **Unix/Linux Security**: File permissions, sensitive paths
10. **GDPR/Privacy Regulations**: Data handling and export compliance

### Research Sources
1. Recent reports of malicious npm packages (2023-2024)
2. Documented cases of malicious Claude/Cursor skills stealing configs
3. Malware analysis of installer script patterns
4. Supply chain security research (Snyk, Sonatype, GitHub)
5. Real-world incidents of telemetry-based data leaks
6. Cost overrun case studies from unbounded AI agent configurations

## Verification Notes

All patterns have been verified against:
- Public documentation (where available)
- Real-world malware samples (sanitized for testing)
- Industry-standard secret detection tools (comparison with TruffleHog, GitLeaks patterns)
- Security best practices from OWASP, NIST, and platform-specific guidelines

## Future Rule Additions

Potential rules not yet implemented:
- Codex-specific configuration rules (pending public documentation)
- MCP server security patterns
- Additional language-specific injection patterns
- More cloud provider credential patterns

## Updates

This document should be updated when:
- New API key formats are released
- New attack patterns are discovered
- Agent platform documentation changes
- Security best practices evolve
