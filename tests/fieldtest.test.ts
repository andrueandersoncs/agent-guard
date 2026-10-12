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
