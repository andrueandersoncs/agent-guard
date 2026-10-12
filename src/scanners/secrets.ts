import * as fs from 'fs';
import * as path from 'path';
import { Finding, SecretPattern } from '../types';
import { checkFileSize, MAX_FILE_BYTES } from '../utils';

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
    // Require AWS secret context on the same line; a bare 40-char quoted string is not enough
    pattern: /aws[\w-]{0,20}secret[\w-]{0,20}['"]?\s*[:=]\s*['"]?(?=[A-Za-z0-9/+=]*[0-9])(?=[A-Za-z0-9/+=]*[A-Z])[A-Za-z0-9/+]{40}(?![A-Za-z0-9/+])/gi, 
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

const SECRET_KEY_HINT = /(?:key|token|secret|passw(?:or)?d|pwd|auth|credential|bearer|private)/i;

/** Outside .env files, only flag high-entropy values that sit next to a secret-like key name. */
function hasSecretContext(content: string, index: number): boolean {
  const lineStart = content.lastIndexOf('\n', index) + 1;
  return SECRET_KEY_HINT.test(content.slice(lineStart, index + 1));
}

function findHighEntropyStrings(content: string, filePath: string): Finding[] {
  const findings: Finding[] = [];
  const base = path.basename(filePath).toLowerCase();
  const isEnvFile = base === '.env' || base.startsWith('.env.') || base.endsWith('.env');
  
  const stringPattern = /['"]([A-Za-z0-9_\-+=\/]{32,200})['"]|(?:^|\s)([A-Za-z0-9_\-+=\/]{40,200})(?:\s|$)/g;
  let match;
  
  while ((match = stringPattern.exec(content)) !== null) {
    const str = match[1] || match[2];
    if (!str) continue;
    
    if (str.length < MIN_STRING_LENGTH || str.length > MAX_STRING_LENGTH) continue;
    
    if (/^[0-9]+$/.test(str)) continue;
    // Subresource-integrity / lockfile hashes
    if (/^sha(?:1|256|384|512)-/.test(str)) continue;
    // File paths and URLs (must start with protocol, domain, or absolute path prefix)
    if (/^(?:https?:\/\/|\/[a-z]+\/|\.\.?\/|[a-z]:\\)/i.test(str) && str.split('/').length > 2) continue;
    if (/^[a-f0-9]+$/i.test(str) && str.length % 2 === 0) continue;
    
    if (!isEnvFile && !hasSecretContext(content, match.index)) continue;

    const entropy = calculateEntropy(str);
    
    if (entropy >= HIGH_ENTROPY_THRESHOLD) {
      const line = content.substring(0, match.index).split('\n').length;
      findings.push({
        type: 'secret',
        severity: 'medium',
        message: `High-entropy string detected (entropy: ${entropy.toFixed(2)})`,
        file: filePath,
        line,
        details: `String: ${maskSecret(str)} (${str.length} chars)`,
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
  
  if (LOCKFILES.has(basename)) {
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
          details: `Matched pattern: ${maskSecret(match[0])}`,
          rule: pattern.name.toLowerCase().replace(/\s+/g, '-')
        });
      }
    }
    
    // Logs/transcripts (.txt/.log) are full of hashes and ids; keep named patterns only there
    if (!['.txt', '.log'].includes(ext)) {
      findings.push(...findHighEntropyStrings(content, filePath));
    }
    
  } catch (error) {
    // Skip files that can't be read as text
  }
  
  return findings;
}

const LOCKFILES = new Set(['package-lock.json', 'yarn.lock', 'pnpm-lock.yaml', 'bun.lock', 'cargo.lock', 'poetry.lock', 'composer.lock', 'gemfile.lock']);

/** Never echo secret material: keep a short prefix for identification only. */
export function maskSecret(value: string): string {
  const prefix = value.slice(0, Math.min(4, Math.floor(value.length / 4)));
  return `${prefix}${'*'.repeat(8)} (redacted)`;
}
