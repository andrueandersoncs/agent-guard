import { Finding, ScanResult, ScanOptions } from './types';
import { scanForSecrets } from './scanners/secrets';
import { scanForRisks } from './scanners/risks';
import { scanAgentConfig } from './scanners/config';
import { getAllFiles, getDirectoryCount } from './utils';
import * as path from 'path';

export function scan(options: ScanOptions): ScanResult {
  const findings: Finding[] = [];
  const scanPath = path.resolve(options.path);
  
  let files: string[] = [];
  let dirCount = 0;
  
  const fs = require('fs');
  const stats = fs.statSync(scanPath);
  
  if (stats.isFile()) {
    files = [scanPath];
    dirCount = 0;
  } else {
    files = getAllFiles(scanPath);
    dirCount = getDirectoryCount(scanPath);
  }
  
  if (options.verbose) {
    console.log(`Scanning ${files.length} files in ${dirCount} directories...`);
  }
  
  for (const file of files) {
    const secretFindings = scanForSecrets(file);
    findings.push(...secretFindings);
    
    const riskFindings = scanForRisks(file);
    findings.push(...riskFindings);
    
    const configFindings = scanAgentConfig(file);
    findings.push(...configFindings);
  }
  
  findings.sort((a, b) => {
    const severityOrder = { high: 0, medium: 1, low: 2, info: 3 };
    return severityOrder[a.severity] - severityOrder[b.severity];
  });
  
  const result: ScanResult = {
    findings,
    scannedFiles: files.length,
    scannedDirectories: dirCount,
    totalFindings: findings.length,
    highSeverityCount: findings.filter(f => f.severity === 'high').length,
    mediumSeverityCount: findings.filter(f => f.severity === 'medium').length,
    lowSeverityCount: findings.filter(f => f.severity === 'low').length,
    infoCount: findings.filter(f => f.severity === 'info').length
  };
  
  return result;
}
