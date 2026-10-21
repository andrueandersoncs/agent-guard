import { describe, it, expect } from 'vitest';
import * as path from 'path';
import { scan } from '../src/scanner';

const fx = (p: string) => path.join(__dirname, 'fixtures/fieldtest', p);
const rules = (p: string) => scan({ path: fx(p), json: false, verbose: false }).findings.map(f => f.rule);

describe('field-test false-positive regressions', () => {
  it('ignores plugin.json where "hooks" is a path string', () => {
    expect(rules('cursor-plugin')).not.toContain('cursor-hook-fail-open');
  });

  it('only flags blocking Cursor hook entries without failClosed', () => {
    const f = scan({ path: fx('cursor-real'), json: false, verbose: false }).findings
      .filter(x => x.rule === 'cursor-hook-fail-open');
    expect(f).toHaveLength(1);
    expect(f[0].message).toContain('beforeShellExecution hook #1');
  });

  it('parses Claude Code nested hooks and skips non-blocking events', () => {
    const f = scan({ path: fx('claude-real'), json: false, verbose: false }).findings
      .filter(x => x.rule === 'claude-hook-fail-open');
    expect(f).toHaveLength(1);
    expect(f[0].message).toContain('PreToolUse');
    expect(f[0].details).toContain('exit 2');
    expect(f[0].details).not.toContain('"failClosed": true');
    expect(f[0].details).toContain('"onFailure": "block"');
  });

  it('accepts Claude Code handlers with onFailure: "block" and flags "continue"', () => {
    const f = scan({ path: fx('claude-onfailure'), json: false, verbose: false }).findings
      .filter(x => x.rule === 'claude-hook-fail-open');
    expect(f).toHaveLength(2);
    expect(f[0].message).toContain('PreToolUse');
    expect(f[1].message).toContain('UserPromptSubmit');
  });

  it('detects Claude Code OTEL prompt logging via env', () => {
    expect(rules('claude-otel')).toContain('otel-prompt-data');
  });

  it('detects Codex otel.log_user_prompt in config.toml only when true', () => {
    const f = scan({ path: fx('codex'), json: false, verbose: false }).findings.filter(x => x.rule === 'otel-prompt-data');
    expect(f).toHaveLength(1);
    expect(f[0].file).toMatch(/config\.toml$/);
  });

  it('does not flag lockfile integrity hashes as high-entropy secrets', () => {
    expect(rules('lock')).toHaveLength(0);
  });

  it('does not flag prose, process.env, 40-char banners or .cursor properties', () => {
    expect(rules('src/prose.md')).toEqual([]);
  });

  it('does not flag curl output piped to an inline python parser', () => {
    expect(rules('src/parse-json.sh')).not.toContain('download-and-execute');
  });

  it('still flags real install-script risks', () => {
    const r = rules('src/install.sh');
    expect(r).toContain('curl-pipe-to-shell');
    expect(r).toContain('claude-config-exfiltration');
  });

  it('never echoes full secret values in details', () => {
    const f = scan({ path: path.join(__dirname, 'fixtures/secrets'), json: false, verbose: false }).findings
      .filter(x => x.type === 'secret');
    expect(f.length).toBeGreaterThan(0);
    for (const x of f) expect(x.details).toContain('(redacted)');
  });
});

describe('code-review regression fixes', () => {
  it('detects base64 secrets with slashes (not treated as paths)', () => {
    const f = scan({ path: fx('review/base64-secret.env'), json: false, verbose: false }).findings
      .filter(x => x.rule === 'high-entropy');
    expect(f.length).toBeGreaterThan(0);
  });

  it('detects nc host port pattern', () => {
    const r = rules('review/nc-call.sh');
    expect(r).toContain('network-call-in-hook');
  });

  it('emits warning for large files and scans first 1MB', () => {
    const f = scan({ path: fx('review/large-file.txt'), json: false, verbose: false }).findings;
    const warnings = f.filter(x => x.rule === 'large-file-warning');
    expect(warnings.length).toBeGreaterThan(0);
    expect(warnings[0].message).toContain('MB');
  });

  it('scans .txt files for risky commands', () => {
    const r = rules('review/risky.txt');
    expect(r).toContain('curl-pipe-to-shell');
  });

  it('scans .log files for risky commands', () => {
    const r = rules('review/risky.log');
    expect(r).toContain('ssh-key-exfiltration');
  });

  it('scans .html files for risky commands', () => {
    const r = rules('review/risky.html');
    expect(r).toContain('download-and-execute');
  });

  it('scans .tsx files for risky commands', () => {
    const r = rules('review/risky.tsx');
    expect(r).toContain('environment-file-access');
  });

  it('scans .jsx files for risky commands', () => {
    const r = rules('review/risky.jsx');
    expect(r).toContain('suspicious-file-upload');
  });

  it('scans .vue files for risky commands', () => {
    const r = rules('review/risky.vue');
    expect(r).toContain('curl-pipe-to-shell');
  });

  it('detects Codex dotted otel.log_user_prompt form', () => {
    const f = scan({ path: fx('review/codex-dotted.toml'), json: false, verbose: false }).findings
      .filter(x => x.rule === 'otel-prompt-data');
    expect(f).toHaveLength(1);
  });

  it('detects Codex [otel] log_user_prompt after array', () => {
    const f = scan({ path: fx('review/codex-after-array.toml'), json: false, verbose: false }).findings
      .filter(x => x.rule === 'otel-prompt-data');
    expect(f).toHaveLength(1);
  });

  it('download-and-execute is case-insensitive', () => {
    const r = rules('review/download-case.sh');
    expect(r).toContain('download-and-execute');
  });

  it('detects path-like high-entropy tokens (/Ab/Cd/...) as secrets', () => {
    const f = scan({ path: fx('review/path-like-secret.env'), json: false, verbose: false }).findings
      .filter(x => x.rule === 'high-entropy');
    expect(f.length).toBeGreaterThan(0);
  });
});
