import chalk from 'chalk';
import { ScanResult, Finding } from '../types';

function getSeverityColor(severity: string): (text: string) => string {
  switch (severity) {
    case 'high':
      return chalk.red.bold;
    case 'medium':
      return chalk.yellow.bold;
    case 'low':
      return chalk.blue.bold;
    case 'info':
      return chalk.cyan.bold;
    default:
      return chalk.white;
  }
}

function getSeveritySymbol(severity: string): string {
  switch (severity) {
    case 'high':
      return '✖';
    case 'medium':
      return '⚠';
    case 'low':
      return '◆';
    case 'info':
      return 'ℹ';
    default:
      return '•';
  }
}

export function reportHuman(result: ScanResult): void {
  console.log('\n' + chalk.bold.underline('Agent Guard Security Scan Report'));
  console.log();
  
  console.log(chalk.gray(`Scanned: ${result.scannedFiles} files in ${result.scannedDirectories} directories`));
  console.log();
  
  if (result.totalFindings === 0) {
    console.log(chalk.green.bold('✓ No security issues found!'));
    console.log();
    return;
  }
  
  console.log(chalk.bold('Summary:'));
  if (result.highSeverityCount > 0) {
    console.log(`  ${chalk.red.bold('High:')}    ${result.highSeverityCount} finding(s)`);
  }
  if (result.mediumSeverityCount > 0) {
    console.log(`  ${chalk.yellow.bold('Medium:')}  ${result.mediumSeverityCount} finding(s)`);
  }
  if (result.lowSeverityCount > 0) {
    console.log(`  ${chalk.blue.bold('Low:')}     ${result.lowSeverityCount} finding(s)`);
  }
  if (result.infoCount > 0) {
    console.log(`  ${chalk.cyan.bold('Info:')}    ${result.infoCount} finding(s)`);
  }
  console.log();
  
  const groupedFindings = groupFindingsByFile(result.findings);
  
  for (const [file, findings] of Object.entries(groupedFindings)) {
    console.log(chalk.bold.white(`\n${file}:`));
    
    for (const finding of findings) {
      const color = getSeverityColor(finding.severity);
      const symbol = getSeveritySymbol(finding.severity);
      const location = finding.line ? `:${finding.line}` : '';
      
      console.log(`  ${color(symbol)} ${color(finding.severity.toUpperCase())} ${location ? chalk.gray(location) : ''}`);
      console.log(`    ${finding.message}`);
      
      if (finding.details) {
        console.log(`    ${chalk.gray(finding.details)}`);
      }
      
      if (finding.rule) {
        console.log(`    ${chalk.gray(`Rule: ${finding.rule}`)}`);
      }
      
      console.log();
    }
  }
  
  if (result.highSeverityCount > 0) {
    console.log(chalk.red.bold('⚠ High severity issues found. Please review and remediate before deployment.'));
  } else if (result.mediumSeverityCount > 0) {
    console.log(chalk.yellow.bold('⚠ Medium severity issues found. Review recommended.'));
  }
  
  console.log();
}

export function reportJson(result: ScanResult): void {
  console.log(JSON.stringify(result, null, 2));
}

function groupFindingsByFile(findings: Finding[]): Record<string, Finding[]> {
  const grouped: Record<string, Finding[]> = {};
  
  for (const finding of findings) {
    if (!grouped[finding.file]) {
      grouped[finding.file] = [];
    }
    grouped[finding.file].push(finding);
  }
  
  return grouped;
}
