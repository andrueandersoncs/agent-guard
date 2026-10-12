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
  
  if (!isClaudeConfig && !isCursorConfig && !basename.endsWith('.json')) {
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
      
      if (claudeConfig.hooks) {
        for (const [hookName, hookConfig] of Object.entries(claudeConfig.hooks)) {
          const failClosed = hookConfig.failClosed ?? false;
          
          if (!failClosed) {
            findings.push({
              type: 'config',
              severity: 'high',
              message: `Claude Code hook "${hookName}" fails open (failClosed: false or not set)`,
              file: filePath,
              details: `If this hook fails, execution continues. Set "failClosed": true to block on failure. Test by causing the hook to fail.`,
              rule: 'claude-hook-fail-open'
            });
          }
        }
      }
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
      
      if (config.hooks) {
        for (const [hookName, hookConfig] of Object.entries(config.hooks)) {
          const failClosed = hookConfig.failClosed ?? false;
          const scope = hookConfig.scope;
          
          if (!failClosed) {
            findings.push({
              type: 'config',
              severity: 'high',
              message: `Cursor hook "${hookName}" fails open (failClosed: false or not set)`,
              file: filePath,
              details: `If this hook fails, execution continues. Set "failClosed": true to block on failure. Test command: ${getTestCommand(hookName)}`,
              rule: 'cursor-hook-fail-open'
            });
          }
          
          if (scope === 'user') {
            findings.push({
              type: 'config',
              severity: 'medium',
              message: `Hook "${hookName}" has user-level scope`,
              file: filePath,
              details: 'Cloud agents do not load user-level hooks. Use project-level scope for cloud agent compatibility.',
              rule: 'user-level-hook'
            });
          }
          
          if (hookConfig.command) {
            const shouldBlock = BLOCKING_COMMANDS.find(cmd => 
              hookConfig.command?.includes(cmd)
            );
            if (shouldBlock) {
              findings.push({
                type: 'config',
                severity: 'info',
                message: `Test: Hook "${hookName}" should block: ${shouldBlock}`,
                file: filePath,
                details: `Test command: ${shouldBlock}`,
                rule: 'hook-test-suggestion'
              });
            }
          }
        }
      }
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
