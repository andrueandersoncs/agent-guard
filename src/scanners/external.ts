import { exec } from 'child_process';
import { promisify } from 'util';
import { Finding } from '../types';

const execAsync = promisify(exec);

export interface ExternalToolResult {
  tool: string;
  available: boolean;
  findings: Finding[];
  rawOutput?: string;
  error?: string;
}

async function checkToolAvailable(command: string): Promise<boolean> {
  try {
    await execAsync(`which ${command}`);
    return true;
  } catch {
    return false;
  }
}

async function runGitleaks(targetPath: string): Promise<ExternalToolResult> {
  const result: ExternalToolResult = {
    tool: 'gitleaks',
    available: false,
    findings: []
  };

  try {
    result.available = await checkToolAvailable('gitleaks');
    if (!result.available) {
      return result;
    }

    const { stdout, stderr } = await execAsync(
      `gitleaks detect --source "${targetPath}" --report-format json --report-path /dev/stdout --no-color || true`,
      { maxBuffer: 10 * 1024 * 1024 }
    );

    result.rawOutput = stdout;

    try {
      const gitleaksResults = JSON.parse(stdout);
      if (Array.isArray(gitleaksResults)) {
        result.findings = gitleaksResults.map((item: any) => ({
          type: 'secret' as const,
          severity: 'high' as const,
          message: `Gitleaks: ${item.RuleID || 'Secret detected'}`,
          file: item.File || targetPath,
          line: item.StartLine || 0,
          details: `Match: ${item.Match?.substring(0, 50) || 'N/A'}... (${item.Description || 'No description'})`,
          rule: `gitleaks-${item.RuleID?.toLowerCase() || 'unknown'}`
        }));
      }
    } catch (parseError) {
      result.error = 'Failed to parse gitleaks JSON output';
    }
  } catch (error) {
    result.error = error instanceof Error ? error.message : String(error);
  }

  return result;
}

async function runGitGuardian(targetPath: string): Promise<ExternalToolResult> {
  const result: ExternalToolResult = {
    tool: 'ggshield',
    available: false,
    findings: []
  };

  try {
    result.available = await checkToolAvailable('ggshield');
    if (!result.available) {
      return result;
    }

    const { stdout, stderr } = await execAsync(
      `ggshield secret scan path "${targetPath}" --json --exit-zero || true`,
      { maxBuffer: 10 * 1024 * 1024 }
    );

    result.rawOutput = stdout;

    try {
      const ggResults = JSON.parse(stdout);
      if (ggResults.secrets_engine_version) {
        const entities = ggResults.entities_with_incidents || [];
        for (const entity of entities) {
          const incidents = entity.incidents || [];
          for (const incident of incidents) {
            for (const occurrence of incident.occurrences || []) {
              result.findings.push({
                type: 'secret' as const,
                severity: 'high' as const,
                message: `GitGuardian: ${incident.policy || 'Secret detected'}`,
                file: entity.filename || targetPath,
                line: occurrence.line_start || 0,
                details: `Match: ${occurrence.match?.substring(0, 50) || 'N/A'}... (Type: ${incident.type || 'unknown'})`,
                rule: `gitguardian-${incident.type?.toLowerCase() || 'unknown'}`
              });
            }
          }
        }
      }
    } catch (parseError) {
      result.error = 'Failed to parse GitGuardian JSON output';
    }
  } catch (error) {
    result.error = error instanceof Error ? error.message : String(error);
  }

  return result;
}

export async function scanWithExternalTools(targetPath: string): Promise<ExternalToolResult[]> {
  const results = await Promise.all([
    runGitleaks(targetPath),
    runGitGuardian(targetPath)
  ]);

  return results;
}

export function getExternalToolsStatus(): Promise<{ gitleaks: boolean; gitguardian: boolean }> {
  return Promise.all([
    checkToolAvailable('gitleaks'),
    checkToolAvailable('ggshield')
  ]).then(([gitleaks, gitguardian]) => ({ gitleaks, gitguardian }));
}
