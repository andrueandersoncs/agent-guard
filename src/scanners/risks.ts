import * as fs from 'fs';
import * as path from 'path';
import { Finding, RiskPattern } from '../types';
import { checkFileSize, MAX_FILE_BYTES } from '../utils';

const RISK_PATTERNS: RiskPattern[] = [
  {
    name: 'Curl pipe to shell',
    pattern: /\bcurl\s+[^|\n]*\|\s*(?:sudo\s+)?(?:ba)?sh\b/gi,
    severity: 'high',
    description: 'Dangerous curl|sh pattern that can execute arbitrary code'
  },
  {
    name: 'Wget pipe to shell',
    pattern: /\bwget\s+[^|\n]*\|\s*(?:sudo\s+)?(?:ba)?sh\b/gi,
    severity: 'high',
    description: 'Dangerous wget|sh pattern that can execute arbitrary code'
  },
  {
    name: 'SSH key exfiltration',
    pattern: /\b(?:cat|curl|wget|nc|netcat|scp)\b[^\n]*(?:[~\/]\.ssh\/(?:id_|authorized_keys)|\bid_rsa\b|\bid_ed25519\b(?!\.pub))/gi,
    severity: 'high',
    description: 'Potential SSH key exfiltration'
  },
  {
    name: 'Claude config exfiltration',
    pattern: /\b(?:cat|curl|wget|nc|netcat|tar|zip)\b[^\n]*(?:~|\$HOME|\$\{HOME\})\/\.claude\b/g,
    severity: 'high',
    description: 'Potential .claude config exfiltration'
  },
  {
    name: 'Cursor config exfiltration',
    pattern: /\b(?:cat|curl|wget|nc|netcat|tar|zip)\b[^\n]*(?:~|\$HOME|\$\{HOME\})\/\.cursor\b/g,
    severity: 'high',
    description: 'Potential .cursor config exfiltration'
  },
  {
    name: 'Environment file access',
    pattern: /\b(?:cat|curl|wget|nc|netcat)\b[^\n]*(?<![\w.$])\.env(?:\.\w+)?\b(?!\.example|\.sample|\.template)/g,
    severity: 'high',
    description: 'Accessing environment files which may contain secrets'
  },
  {
    name: 'Base64 encoded command',
    pattern: /(?:bash|sh|python|node|eval)\s+(?:-c\s+)?\$\(.*base64/gi,
    severity: 'high',
    description: 'Base64 encoded command execution (obfuscation)'
  },
  {
    name: 'Base64 decode in script',
    pattern: /base64\s+(?:-d|--decode)/gi,
    severity: 'medium',
    description: 'Base64 decoding often used for obfuscation'
  },
  {
    name: 'Eval with variable',
    pattern: /eval\s*\(/gi,
    severity: 'medium',
    description: 'Dynamic code evaluation can be dangerous'
  },
  {
    name: 'Network call in hook',
    pattern: /\b(?:curl|wget)\s+(?:-\S+\s+)*['"]?https?:\/\/|\b(?:nc|netcat)\s+(?:-\S+\s+)*\S+\s+\d+/gi,
    severity: 'medium',
    description: 'Network call in installation or hook script'
  },
  {
    name: 'Suspicious file upload',
    pattern: /curl\s+.*-[FfXd]\s+@/gi,
    severity: 'high',
    description: 'File upload via curl'
  },
  {
    name: 'Reverse shell pattern',
    pattern: /(?:nc|netcat|bash|sh).*-[el].*\/dev\/tcp/gi,
    severity: 'high',
    description: 'Potential reverse shell'
  },
  {
    name: 'Hidden directory write',
    pattern: /(?:echo|cat|tee|>|>>)\s+.*\/\.\w+\//gi,
    severity: 'medium',
    description: 'Writing to hidden directories'
  },
  {
    name: 'chmod 777',
    pattern: /chmod\s+777/gi,
    severity: 'medium',
    description: 'Overly permissive file permissions'
  },
  {
    name: 'Download and execute',
    pattern: /\b(?:curl|wget)\s[^\n]*(?:\||;|&&)\s*(?:sudo\s+(?:-\S+\s+)*)?(?:bash|sh|python3?|node)\b(?!\s+-[ce]\b)/g,
    severity: 'high',
    description: 'Download and immediate execution pattern'
  },
  {
    name: 'Hex encoded command',
    pattern: /\\x[0-9a-f]{2}.*\\x[0-9a-f]{2}.*\\x[0-9a-f]{2}/gi,
    severity: 'medium',
    description: 'Hex-encoded content (potential obfuscation)'
  }
];

const SENSITIVE_FILE_PATHS = [
  '~/.ssh',
  '~/.claude',
  '~/.cursor',
  '~/.aws',
  '~/.config',
  '/etc/passwd',
  '/etc/shadow',
  '.env',
  '.env.local',
  'id_rsa',
  'id_ed25519'
];

const HOOK_FILE_PATTERNS = [
  'preinstall',
  'postinstall',
  'install.sh',
  'setup.sh',
  'init.sh',
  'bootstrap',
  'package.json'
];

export function scanForRisks(filePath: string): Finding[] {
  const findings: Finding[] = [];
  
  if (!fs.existsSync(filePath)) {
    return findings;
  }
  
  const stats = fs.statSync(filePath);
  if (!stats.isFile()) {
    return findings;
  }
  
  if (!isRiskScannable(filePath)) {
    return findings;
  }

  const sizeWarning = checkFileSize(filePath);
  if (sizeWarning) {
    findings.push({
      type: 'config',
      severity: 'info',
      message: `Large file: ${(sizeWarning.actualSize / (1024 * 1024)).toFixed(2)} MB (scanning first 1 MB only)`,
      file: filePath,
      details: `File size: ${sizeWarning.actualSize} bytes. Large files are scanned partially to avoid performance issues.`,
      rule: 'large-file-warning'
    });
  }

  try {
    const fd = fs.openSync(filePath, 'r');
    const buffer = Buffer.alloc(MAX_FILE_BYTES);
    const bytesRead = fs.readSync(fd, buffer, 0, MAX_FILE_BYTES, 0);
    fs.closeSync(fd);
    const content = buffer.slice(0, bytesRead).toString('utf-8');
    const basename = path.basename(filePath).toLowerCase();
    
    const isHookFile = HOOK_FILE_PATTERNS.some(pattern => 
      basename.includes(pattern)
    );
    
    for (const riskPattern of RISK_PATTERNS) {
      if (riskPattern.name === 'Network call in hook' && !isHookFile && !isScriptFile(filePath)) continue;
      const matches = content.matchAll(riskPattern.pattern);
      for (const match of matches) {
        const line = content.substring(0, match.index).split('\n').length;
        
        let severity = riskPattern.severity;
        if (isHookFile && riskPattern.severity === 'medium') {
          severity = 'high';
        }
        
        findings.push({
          type: 'risk',
          severity,
          message: `${riskPattern.name}: ${riskPattern.description}`,
          file: filePath,
          line,
          details: `Matched: ${match[0].substring(0, 50)}${match[0].length > 50 ? '...' : ''}`,
          rule: riskPattern.name.toLowerCase().replace(/\s+/g, '-')
        });
      }
    }
    
    for (const sensitivePath of SENSITIVE_FILE_PATHS) {
      if (!content.includes(sensitivePath)) continue;
      const escaped = sensitivePath.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      // Require a path-like boundary so "process.env" or "import.meta.env" don't match ".env"
      const regex = new RegExp(`(?<![\\w.$])${escaped}(?![\\w-])`, 'g');
      const matches = [...content.matchAll(regex)];
      if (matches.length === 0) continue;
      // One finding per path per file: a script that mentions .env 30 times is one thing to review
      const lines = matches.map(m => content.substring(0, m.index).split('\n').length);
      findings.push({
        type: 'risk',
        severity: isHookFile || isScriptFile(filePath) ? 'medium' : 'low',
        message: `Reference to sensitive path: ${sensitivePath}`,
        file: filePath,
        line: lines[0],
        details: `Referenced ${matches.length}x (lines ${lines.slice(0, 5).join(', ')}${lines.length > 5 ? ', ...' : ''})`,
        rule: 'sensitive-path-access'
      });
    }
    
    if (basename === 'package.json') {
      try {
        const pkg = JSON.parse(content);
        if (pkg.scripts) {
          for (const [scriptName, scriptContent] of Object.entries(pkg.scripts)) {
            if (typeof scriptContent !== 'string') continue;
            
            if (scriptContent.includes('curl') || scriptContent.includes('wget')) {
              findings.push({
                type: 'risk',
                severity: 'high',
                message: `Network call in npm script "${scriptName}"`,
                file: filePath,
                details: `Script: ${scriptContent}`,
                rule: 'npm-script-network-call'
              });
            }
          }
        }
      } catch {
        // Not valid JSON or doesn't have scripts
      }
    }
    
  } catch (error) {
    // Skip files that can't be read
  }
  
  return findings;
}

// App source code (Swift, Rust, Go, ...) is not an agent config or install script;
// scanning it for shell patterns produced mostly false positives in field tests.
const NON_AGENT_SOURCE_EXTS = new Set([
  '.swift', '.rs', '.go', '.java', '.kt', '.c', '.cc', '.cpp', '.h', '.hpp', '.m', '.mm',
  '.cs', '.svelte', '.css', '.scss', '.lock', '.map', '.svg'
]);
const LOCKFILES = new Set(['package-lock.json', 'yarn.lock', 'pnpm-lock.yaml', 'bun.lock', 'cargo.lock', 'poetry.lock', 'composer.lock', 'gemfile.lock']);

export function isRiskScannable(filePath: string): boolean {
  const base = path.basename(filePath).toLowerCase();
  if (LOCKFILES.has(base)) return false;
  return !NON_AGENT_SOURCE_EXTS.has(path.extname(base));
}

function isScriptFile(filePath: string): boolean {
  const ext = path.extname(filePath).toLowerCase();
  return ['.sh', '.bash', '.zsh', '.ps1', '.cmd', '.bat', ''].includes(ext) || /(^|\/)hooks?\//.test(filePath);
}
