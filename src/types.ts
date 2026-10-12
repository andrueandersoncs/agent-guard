export type Severity = 'high' | 'medium' | 'low' | 'info';

export interface Finding {
  type: 'secret' | 'risk' | 'config';
  severity: Severity;
  message: string;
  file: string;
  line?: number;
  details?: string;
  rule?: string;
}

export interface ScanResult {
  findings: Finding[];
  scannedFiles: number;
  scannedDirectories: number;
  totalFindings: number;
  highSeverityCount: number;
  mediumSeverityCount: number;
  lowSeverityCount: number;
  infoCount: number;
}

export interface ScanOptions {
  path: string;
  json?: boolean;
  verbose?: boolean;
}

export interface SecretPattern {
  name: string;
  pattern: RegExp;
  severity: Severity;
}

export interface RiskPattern {
  name: string;
  pattern: RegExp;
  severity: Severity;
  description: string;
}
