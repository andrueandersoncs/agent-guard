import * as fs from 'fs';
import * as path from 'path';
import { Finding } from '../types';

interface ClaudeConfig {
  helpers?: Array<{
    name?: string;
    model?: string;
    [key: string]: any;
  }>;
  subagents?: Array<{
    name?: string;
    model?: string;
    [key: string]: any;
  }>;
  'code-review'?: {
    reviewers?: Array<{
      name?: string;
      model?: string;
      [key: string]: any;
    }>;
  };
  hooks?: {
    [key: string]: {
      command?: string;
      failClosed?: boolean;
      scope?: string;
      [key: string]: any;
    };
  };
  telemetry?: {
    enabled?: boolean;
    sendPrompts?: boolean;
    sendResponses?: boolean;
    endpoint?: string;
  };
  openTelemetry?: {
    enabled?: boolean;
    endpoint?: string;
    sendPromptData?: boolean;
  };
  model?: string;
  [key: string]: any;
}

interface CursorConfig {
  hooks?: {
    [key: string]: {
      command?: string;
      failClosed?: boolean;
      scope?: string;
      [key: string]: any;
    };
  };
  telemetry?: {
    enabled?: boolean;
    sendDiagnostics?: boolean;
    sendPrompts?: boolean;
  };
  [key: string]: any;
}

const EXPENSIVE_MODELS = [
  'claude-opus',
  'gpt-4',
  'o1',
  'o3'
];

const BLOCKING_COMMANDS = [
  'rm -rf /',
  'curl http://evil.com',
  'cat ~/.ssh/id_rsa',
  'env | grep SECRET'
];

export function scanAgentConfig(filePath: string): Finding[] {
  const findings: Finding[] = [];
  
  if (!fs.existsSync(filePath)) {
    return findings;
  }
  
  const stats = fs.statSync(filePath);
  if (!stats.isFile()) {
    return findings;
  }
  
  const basename = path.basename(filePath).toLowerCase();
  const dirname = path.dirname(filePath);
  
  const isClaudeConfig = basename.includes('claude') || 
                         dirname.includes('.claude') ||
                         basename === 'codex.json' ||
                         dirname.includes('.codex');
  
  const isCursorConfig = basename.includes('cursor') || 
                         dirname.includes('.cursor');
  
  if (basename.endsWith('.toml') && (isClaudeConfig || dirname.includes('codex') || basename.includes('codex'))) {
    return auditCodexToml(filePath);
  }

  if (!basename.endsWith('.json')) {
    return findings;
  }
  
  try {
    const content = fs.readFileSync(filePath, 'utf-8');
    let config: ClaudeConfig | CursorConfig;
    
    try {
      config = JSON.parse(content);
    } catch {
      return findings;
    }
    
    if (config && typeof config === 'object') {
      findings.push(...auditHooks(config, filePath, isCursorConfig, isClaudeConfig));
    }

    if (isClaudeConfig) {
      const claudeConfig = config as ClaudeConfig;
      
      if (claudeConfig.helpers) {
        for (const helper of claudeConfig.helpers) {
          if (!helper.model) {
            findings.push({
              type: 'config',
              severity: 'medium',
              message: `Helper "${helper.name || 'unnamed'}" has no model specified`,
              file: filePath,
              details: 'Helpers without explicit models may use expensive defaults or fail unexpectedly',
              rule: 'helper-no-model'
            });
          }
        }
      }
      
      if (claudeConfig.subagents) {
        for (const subagent of claudeConfig.subagents) {
          if (!subagent.model) {
            findings.push({
              type: 'config',
              severity: 'medium',
              message: `Subagent "${subagent.name || 'unnamed'}" has no model specified`,
              file: filePath,
              details: 'Subagents without explicit models may use expensive defaults',
              rule: 'subagent-no-model'
            });
          }
        }
      }
      
      if (claudeConfig['code-review']?.reviewers) {
        for (const reviewer of claudeConfig['code-review'].reviewers) {
          if (!reviewer.model) {
            findings.push({
              type: 'config',
              severity: 'medium',
              message: `Code reviewer "${reviewer.name || 'unnamed'}" has no model specified`,
              file: filePath,
              details: 'Reviewers without explicit models may use expensive defaults',
              rule: 'reviewer-no-model'
            });
          }
        }
      }
      
      const allModels: string[] = [];
      if (claudeConfig.model) allModels.push(claudeConfig.model);
      if (claudeConfig.helpers) {
        allModels.push(...claudeConfig.helpers.map(h => h.model).filter(Boolean) as string[]);
      }
      if (claudeConfig.subagents) {
        allModels.push(...claudeConfig.subagents.map(s => s.model).filter(Boolean) as string[]);
      }
      if (claudeConfig['code-review']?.reviewers) {
        allModels.push(...claudeConfig['code-review'].reviewers.map(r => r.model).filter(Boolean) as string[]);
      }
      
      const uniqueModels = [...new Set(allModels)];
      if (uniqueModels.length > 2) {
        findings.push({
          type: 'config',
          severity: 'medium',
          message: `Multiple different models configured (${uniqueModels.length})`,
          file: filePath,
          details: `Models: ${uniqueModels.join(', ')}. Model switching can reset prompt caches and increase costs.`,
          rule: 'model-switching'
        });
      }
      
      const hasExpensiveModel = allModels.some(model => 
        EXPENSIVE_MODELS.some(expensive => model?.includes(expensive))
      );
      
      if (hasExpensiveModel) {
        findings.push({
          type: 'config',
          severity: 'info',
          message: 'Configuration uses expensive models',
          file: filePath,
          details: `Models like Opus, GPT-4, or O1/O3 can significantly increase costs`,
          rule: 'expensive-model'
        });
      }
      
      if (claudeConfig.maxTokens && claudeConfig.maxTokens > 100000) {
        findings.push({
          type: 'config',
          severity: 'medium',
          message: `Very large context window configured: ${claudeConfig.maxTokens} tokens`,
          file: filePath,
          details: 'Large context windows can significantly increase costs',
          rule: 'large-context'
        });
      }
      
      if (claudeConfig.telemetry?.enabled || claudeConfig.telemetry?.sendPrompts || claudeConfig.telemetry?.sendResponses) {
        findings.push({
          type: 'config',
          severity: 'high',
          message: 'Prompt telemetry is enabled',
          file: filePath,
          details: 'Sending prompts/responses to telemetry endpoints may leak sensitive data. Review the endpoint and consider disabling.',
          rule: 'telemetry-enabled'
        });
      }
      
      if (claudeConfig.openTelemetry?.enabled || claudeConfig.openTelemetry?.sendPromptData) {
        const endpoint = claudeConfig.openTelemetry?.endpoint || 'not specified';
        findings.push({
          type: 'config',
          severity: 'high',
          message: 'OpenTelemetry is configured to send prompt data',
          file: filePath,
          details: `Endpoint: ${endpoint}. Verify this endpoint is trusted and compliant with your data privacy requirements.`,
          rule: 'otel-prompt-data'
        });
      }
      
      findings.push(...auditClaudeEnvTelemetry(claudeConfig, filePath));
    }

    if (isCursorConfig) {
      const cursorConfig = config as CursorConfig;
      
      if (cursorConfig.telemetry?.enabled || cursorConfig.telemetry?.sendPrompts || cursorConfig.telemetry?.sendDiagnostics) {
        findings.push({
          type: 'config',
          severity: 'medium',
          message: 'Cursor telemetry is enabled',
          file: filePath,
          details: 'Review what data is being sent. Consider disabling sendPrompts if working with sensitive code.',
          rule: 'cursor-telemetry-enabled'
        });
      }
      
      // hooks handled by auditHooks below
    }
    
  } catch (error) {
    // Skip files that can't be processed
  }
  
  return findings;
}

function getTestCommand(hookName: string): string {
  const testCommands: Record<string, string> = {
    'pre-commit': 'git commit -m "test"',
    'pre-push': 'git push',
    'pre-merge': 'git merge test-branch',
    'pre-task': 'cursor agent run-task',
    'pre-edit': 'any file edit operation'
  };
  
  return testCommands[hookName] || `trigger ${hookName} hook`;
}

// Events that can actually block an action. Fail-open only matters for these;
// observational hooks (sessionStart, after*, stop, preCompact, ...) cannot block.
const CURSOR_BLOCKING_EVENTS = new Set([
  'beforeShellExecution', 'beforeMCPExecution', 'beforeReadFile', 'beforeTabFileRead',
  'preToolUse', 'subagentStart', 'beforeSubmitPrompt'
]);
const CLAUDE_BLOCKING_EVENTS = new Set([
  'PreToolUse', 'PermissionRequest', 'UserPromptSubmit'
]);

function isPlainObject(v: unknown): v is Record<string, any> {
  return !!v && typeof v === 'object' && !Array.isArray(v);
}

export function auditHooks(config: Record<string, any>, filePath: string, isCursorPath: boolean, isClaudePath = false): Finding[] {
  const findings: Finding[] = [];
  const hooks = config.hooks;
  // e.g. plugin.json uses "hooks": "./hooks/hooks.json" (a path, not hook definitions)
  if (!isPlainObject(hooks)) return findings;

  for (const [event, value] of Object.entries(hooks)) {
    if (Array.isArray(value)) {
      const claudeStyle = value.some(e => isPlainObject(e) && Array.isArray(e.hooks));
      if (claudeStyle) {
        if (!CLAUDE_BLOCKING_EVENTS.has(event)) continue;
        const commands = value.flatMap(e => (isPlainObject(e) && Array.isArray(e.hooks) ? e.hooks : []))
          .filter(h => isPlainObject(h) && (h.type ?? 'command') === 'command');
        if (commands.length === 0) continue;
        findings.push({
          type: 'config',
          severity: 'medium',
          message: `Claude Code ${event} hook fails open unless its script exits 2 on internal errors`,
          file: filePath,
          details: 'Claude Code only blocks on exit code 2; crashes, timeouts and other non-zero exits let the action proceed. ' +
            'There is no failClosed setting: make the script trap errors and exit 2. Test by making the script throw.',
          rule: 'claude-hook-fail-open'
        });
      } else {
        if (!CURSOR_BLOCKING_EVENTS.has(event)) continue;
        value.forEach((entry, i) => {
          if (!isPlainObject(entry)) return;
          if (entry.type === 'prompt') return;
          if (entry.failClosed === true) return;
          findings.push({
            type: 'config',
            severity: 'high',
            message: `Cursor ${event} hook #${i + 1} fails open (failClosed not set)`,
            file: filePath,
            details: `Crashes, timeouts and non-zero exits other than 2 let the action through. Add "failClosed": true to this entry. Command: ${String(entry.command ?? '').slice(0, 80)}`,
            rule: 'cursor-hook-fail-open'
          });
        });
      }
    } else if (isPlainObject(value) && (isCursorPath || isClaudePath)) {
      // Legacy object-per-hook format
      const label = isCursorPath ? 'Cursor' : 'Claude Code';
      if (value.failClosed !== true) {
        findings.push({
          type: 'config',
          severity: 'high',
          message: `${label} hook "${event}" fails open (failClosed: false or not set)`,
          file: filePath,
          details: `If this hook fails, execution continues. Set "failClosed": true to block on failure. Test command: ${getTestCommand(event)}`,
          rule: isCursorPath ? 'cursor-hook-fail-open' : 'claude-hook-fail-open'
        });
      }
      if (value.scope === 'user') {
        findings.push({
          type: 'config',
          severity: 'medium',
          message: `Hook "${event}" has user-level scope`,
          file: filePath,
          details: 'Cloud agents do not load user-level hooks. Use project-level scope for cloud agent compatibility.',
          rule: 'user-level-hook'
        });
      }
    }
  }
  return findings;
}

function truthyFlag(v: unknown): boolean {
  return v === true || v === 1 || v === '1' || (typeof v === 'string' && v.toLowerCase() === 'true');
}

function auditClaudeEnvTelemetry(config: Record<string, any>, filePath: string): Finding[] {
  const env = isPlainObject(config.env) ? config.env : {};
  if (truthyFlag(env.CLAUDE_CODE_ENABLE_TELEMETRY) && truthyFlag(env.OTEL_LOG_USER_PROMPTS)) {
    return [{
      type: 'config',
      severity: 'high',
      message: 'Claude Code OpenTelemetry exports user prompt text (OTEL_LOG_USER_PROMPTS=1)',
      file: filePath,
      details: `Endpoint: ${env.OTEL_EXPORTER_OTLP_ENDPOINT ? 'set in env' : 'not specified'}. Verify the collector is trusted.`,
      rule: 'otel-prompt-data'
    }];
  }
  return [];
}

export function auditCodexToml(filePath: string): Finding[] {
  let content: string;
  try { content = fs.readFileSync(filePath, 'utf-8'); } catch { return []; }
  const findings: Finding[] = [];
  const otelSection = /^\[otel\][^\[]*/m.exec(content)?.[0] ?? '';
  if (/^\s*log_user_prompt\s*=\s*true/m.test(otelSection)) {
    findings.push({
      type: 'config',
      severity: 'high',
      message: 'Codex OpenTelemetry exports user prompt text (otel.log_user_prompt = true)',
      file: filePath,
      details: 'Prompts are redacted by default; this setting sends them to the configured exporter.',
      rule: 'otel-prompt-data'
    });
  }
  return findings;
}
