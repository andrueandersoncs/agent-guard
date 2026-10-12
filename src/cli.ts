#!/usr/bin/env node

import { Command } from 'commander';
import { scan } from './scanner';
import { reportHuman, reportJson } from './reporters/reporter';
import { scanWithExternalTools, getExternalToolsStatus } from './scanners/external';
import * as path from 'path';
import * as fs from 'fs';

const program = new Command();

program
  .name('agent-guard')
  .description('CLI tool to scan AI agent configurations for security risks and secrets')
  .version('1.0.0');

program
  .argument('[path]', 'Path to scan (directory or file)', '.')
  .option('-j, --json', 'Output results in JSON format')
  .option('-v, --verbose', 'Verbose output')
  .option('--with-external', 'Also run gitleaks and GitGuardian if installed')
  .action(async (scanPath: string, options) => {
    const resolvedPath = path.resolve(scanPath);
    
    if (!fs.existsSync(resolvedPath)) {
      console.error(`Error: Path does not exist: ${resolvedPath}`);
      process.exit(1);
    }
    
    const result = scan({
      path: resolvedPath,
      json: options.json,
      verbose: options.verbose
    });
    
    if (options.withExternal) {
      if (options.verbose) {
        const status = await getExternalToolsStatus();
        console.log('\nExternal tools status:');
        console.log(`  gitleaks: ${status.gitleaks ? '✓ available' : '✗ not found'}`);
        console.log(`  GitGuardian (ggshield): ${status.gitguardian ? '✓ available' : '✗ not found'}`);
      }
      
      const externalResults = await scanWithExternalTools(resolvedPath);
      for (const toolResult of externalResults) {
        if (toolResult.available) {
          result.findings.push(...toolResult.findings);
          if (options.verbose) {
            console.log(`\n${toolResult.tool}: Found ${toolResult.findings.length} additional findings`);
          }
        }
      }
      
      result.totalFindings = result.findings.length;
      result.highSeverityCount = result.findings.filter(f => f.severity === 'high').length;
      result.mediumSeverityCount = result.findings.filter(f => f.severity === 'medium').length;
      result.lowSeverityCount = result.findings.filter(f => f.severity === 'low').length;
      result.infoCount = result.findings.filter(f => f.severity === 'info').length;
    }
    
    if (options.json) {
      reportJson(result);
    } else {
      reportHuman(result);
    }
    
    // Set exitCode instead of calling process.exit() so large JSON output
    // written to a pipe is fully flushed before the process ends.
    process.exitCode = result.highSeverityCount > 0 ? 1 : 0;
  });

program.parse();
