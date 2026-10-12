import * as fs from 'fs';
import * as path from 'path';
import { Finding, SecretPattern } from '../types';

const SECRET_PATTERNS: SecretPattern[] = [
  {
    name: 'OpenAI API Key',
    pattern: /sk-[A-Za-z0-9]{48}/g,
    severity: 'high'
  },
  {
    name: 'OpenAI API Key (new format)',
    pattern: /sk-proj-[A-Za-z0-9_-]{43,}/g,
    severity: 'high'
  },
  {
    name: 'Anthropic API Key',
    pattern: /sk-ant-api03-[A-Za-z0-9_-]{95,}/g,
    severity: 'high'
  },
  {
    name: 'GitHub Token',
    pattern: /gh[ps]_[A-Za-z0-9]{36,}/g,
    severity: 'high'
  },
  {
    name: 'Generic API Key',
    pattern: /(?:api[_-]?key|apikey|access[_-]?token|secret[_-]?key)[\s:=]+['"]?([A-Za-z0-9_\-]{32,})['"]?/gi,
    severity: 'high'
  },
  {
    name: 'AWS Access Key ID',
    pattern: /AKIA[0-9A-Z]{16}/g,
    severity: 'high'
  },
  {
    name: 'AWS Secret Access Key',
    pattern: /(?:aws.{0,20})?(?:secret.{0,20})?['\"][A-Za-z0-9/+=]{40}['\"]/, 
    severity: 'high'
  },
  {
    name: 'Slack Token',
    pattern: /xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24,}/g,
    severity: 'high'
  },
  {
    name: 'Private Key',
    pattern: /-----BEGIN (RSA |OPENSSH |EC )?PRIVATE KEY-----/g,
    severity: 'high'
  },
  {
    name: 'Google API Key',
    pattern: /AIza[0-9A-Za-z_-]{35}/g,
    severity: 'high'
  },
  {
    name: 'Google OAuth',
    pattern: /[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com/g,
    severity: 'high'
  },
  {
    name: 'Stripe API Key',
    pattern: /sk_live_[0-9a-zA-Z]{24,}/g,
    severity: 'high'
  },
  {
    name: 'Bearer Token',
    pattern: /bearer\s+[a-zA-Z0-9_\-\.=]{20,}/gi,
    severity: 'medium'
  },
  {
    name: 'JWT Token',
    pattern: /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g,
    severity: 'medium'
  }
];

const HIGH_ENTROPY_THRESHOLD = 4.5;
const MIN_STRING_LENGTH = 32;
const MAX_STRING_LENGTH = 200;

function calculateEntropy(str: string): number {
  const freq = new Map<string, number>();
  for (const char of str) {
    freq.set(char, (freq.get(char) || 0) + 1);
  }
  
  let entropy = 0;
  const len = str.length;
  for (const count of freq.values()) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }
  
  return entropy;
}

function findHighEntropyStrings(content: string, filePath: string): Finding[] {
  const findings: Finding[] = [];
  
  const stringPattern = /['"]([A-Za-z0-9_\-+=\/]{32,200})['"]|(?:^|\s)([A-Za-z0-9_\-+=\/]{40,200})(?:\s|$)/g;
  let match;
  
  while ((match = stringPattern.exec(content)) !== null) {
    const str = match[1] || match[2];
    if (!str) continue;
    
    if (str.length < MIN_STRING_LENGTH || str.length > MAX_STRING_LENGTH) continue;
    
    if (/^[0-9]+$/.test(str)) continue;
    if (/^[a-f0-9]+$/i.test(str) && str.length % 2 === 0) continue;
    
    const entropy = calculateEntropy(str);
    
    if (entropy >= HIGH_ENTROPY_THRESHOLD) {
      const line = content.substring(0, match.index).split('\n').length;
      findings.push({
        type: 'secret',
        severity: 'medium',
        message: `High-entropy string detected (entropy: ${entropy.toFixed(2)})`,
        file: filePath,
        line,
        details: `String: ${str.substring(0, 20)}... (${str.length} chars)`,
        rule: 'high-entropy'
      });
    }
  }
  
  return findings;
}

export function scanForSecrets(filePath: string): Finding[] {
  const findings: Finding[] = [];
  
  if (!fs.existsSync(filePath)) {
    return findings;
  }
  
  const stats = fs.statSync(filePath);
  if (!stats.isFile()) {
    return findings;
  }
  
  const ext = path.extname(filePath).toLowerCase();
  const supportedExts = ['.json', '.yaml', '.yml', '.toml', '.env', '.sh', '.bash', '.zsh', 
                         '.js', '.ts', '.py', '.md', '.txt', '.config', '.conf', ''];
  
  const basename = path.basename(filePath).toLowerCase();
  if (!supportedExts.includes(ext) && 
      !basename.includes('config') && 
      !basename.includes('secret') &&
      !basename.includes('.env')) {
    return findings;
  }
  
  try {
    const content = fs.readFileSync(filePath, 'utf-8');
    
    for (const pattern of SECRET_PATTERNS) {
      const matches = content.matchAll(pattern.pattern);
      for (const match of matches) {
        const line = content.substring(0, match.index).split('\n').length;
        findings.push({
          type: 'secret',
          severity: pattern.severity,
          message: `${pattern.name} detected`,
          file: filePath,
          line,
          details: `Matched pattern: ${match[0].substring(0, 20)}...`,
          rule: pattern.name.toLowerCase().replace(/\s+/g, '-')
        });
      }
    }
    
    findings.push(...findHighEntropyStrings(content, filePath));
    
  } catch (error) {
    // Skip files that can't be read as text
  }
  
  return findings;
}
