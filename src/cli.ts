#!/usr/bin/env node

import { Command } from 'commander';
import { scan } from './scanner';
import { reportHuman, reportJson } from './reporters/reporter';
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
  .action((scanPath: string, options) => {
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
    
    if (options.json) {
      reportJson(result);
    } else {
      reportHuman(result);
    }
    
    if (result.highSeverityCount > 0) {
      process.exit(1);
    }
    
    process.exit(0);
  });

program.parse();
