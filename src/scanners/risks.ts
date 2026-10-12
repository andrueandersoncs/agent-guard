import * as fs from 'fs';
import * as path from 'path';
import { Finding, RiskPattern } from '../types';

const RISK_PATTERNS: RiskPattern[] = [
  {
    name: 'Curl pipe to shell',
    pattern: /curl\s+[^|]*\|\s*(ba)?sh/gi,
    severity: 'high',
    description: 'Dangerous curl|sh pattern that can execute arbitrary code'
  },
  {
    name: 'Wget pipe to shell',
    pattern: /wget\s+[^|]*\|\s*(ba)?sh/gi,
    severity: 'high',
    description: 'Dangerous wget|sh pattern that can execute arbitrary code'
  },
  {
    name: 'SSH key exfiltration',
    pattern: /(?:cat|curl|wget|nc|netcat).*(?:\.ssh|id_rsa|id_ed25519|authorized_keys)/gi,
    severity: 'high',
    description: 'Potential SSH key exfiltration'
  },
  {
    name: 'Claude config exfiltration',
    pattern: /(?:cat|curl|wget|nc|netcat|tar|zip).*\.claude/gi,
    severity: 'high',
    description: 'Potential .claude config exfiltration'
  },
  {
    name: 'Cursor config exfiltration',
    pattern: /(?:cat|curl|wget|nc|netcat|tar|zip).*\.cursor/gi,
    severity: 'high',
    description: 'Potential .cursor config exfiltration'
  },
  {
    name: 'Environment file access',
    pattern: /(?:cat|curl|wget|nc|netcat).*\.env/gi,
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
    pattern: /(?:curl|wget|nc|netcat|fetch)\s+(?:http|https):\/\//gi,
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
    pattern: /(?:curl|wget).*(?:\||;|&&)\s*(?:bash|sh|python|node)/gi,
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
  
  try {
    const content = fs.readFileSync(filePath, 'utf-8');
    const basename = path.basename(filePath).toLowerCase();
    
    const isHookFile = HOOK_FILE_PATTERNS.some(pattern => 
      basename.includes(pattern)
    );
    
    for (const riskPattern of RISK_PATTERNS) {
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
      if (content.includes(sensitivePath)) {
        const regex = new RegExp(sensitivePath.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'g');
        const matches = content.matchAll(regex);
        for (const match of matches) {
          const line = content.substring(0, match.index).split('\n').length;
          findings.push({
            type: 'risk',
            severity: 'medium',
            message: `Reference to sensitive path: ${sensitivePath}`,
            file: filePath,
            line,
            details: 'Script accesses sensitive file or directory',
            rule: 'sensitive-path-access'
          });
        }
      }
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
