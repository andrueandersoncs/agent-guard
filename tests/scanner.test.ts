import { describe, it, expect } from 'vitest';
import { scan } from '../src/scanner';
import * as path from 'path';

describe('Agent Guard Scanner', () => {
  describe('Secret Detection', () => {
    it('should detect API keys in .env files', () => {
      const result = scan({
        path: path.join(__dirname, 'fixtures/secrets/api-keys.env'),
        json: false,
        verbose: false
      });
      
      expect(result.totalFindings).toBeGreaterThan(0);
      expect(result.highSeverityCount).toBeGreaterThan(0);
      
      const openAiKey = result.findings.find(f => 
        f.message.includes('OpenAI API Key')
      );
      expect(openAiKey).toBeDefined();
      expect(openAiKey?.severity).toBe('high');
    });
    
    it('should detect multiple secret types in config files', () => {
      const result = scan({
        path: path.join(__dirname, 'fixtures/secrets/config.json'),
        json: false,
        verbose: false
      });
      
      expect(result.totalFindings).toBeGreaterThan(0);
      
      const jwtToken = result.findings.find(f => 
        f.message.includes('JWT Token')
      );
      expect(jwtToken).toBeDefined();
    });
    
    it('should detect high-entropy strings', () => {
      const result = scan({
        path: path.join(__dirname, 'fixtures/secrets/config.json'),
        json: false,
        verbose: false
      });
      
      const highEntropy = result.findings.find(f => 
        f.message.includes('High-entropy string')
      );
      expect(highEntropy).toBeDefined();
    });
  });
  
  describe('Risk Detection', () => {
    it('should detect curl pipe to shell', () => {
      const result = scan({
        path: path.join(__dirname, 'fixtures/risks/malicious-install.sh'),
        json: false,
        verbose: false
      });
      
      expect(result.totalFindings).toBeGreaterThan(0);
      expect(result.highSeverityCount).toBeGreaterThan(0);
      
      const curlShell = result.findings.find(f => 
        f.message.includes('curl') && f.message.includes('sh')
      );
      expect(curlShell).toBeDefined();
    });
    
    it('should detect SSH key exfiltration', () => {
      const result = scan({
        path: path.join(__dirname, 'fixtures/risks/malicious-install.sh'),
        json: false,
        verbose: false
      });
      
      const sshExfil = result.findings.find(f => 
        f.message.includes('SSH key')
      );
      expect(sshExfil).toBeDefined();
      expect(sshExfil?.severity).toBe('high');
    });
    
    it('should detect base64 obfuscation', () => {
      const result = scan({
        path: path.join(__dirname, 'fixtures/risks/malicious-install.sh'),
        json: false,
        verbose: false
      });
      
      const base64 = result.findings.find(f => 
        f.message.includes('Base64')
      );
      expect(base64).toBeDefined();
    });
    
    it('should detect config file exfiltration', () => {
      const result = scan({
        path: path.join(__dirname, 'fixtures/risks/malicious-install.sh'),
        json: false,
        verbose: false
      });
      
      const claudeExfil = result.findings.find(f => 
        f.message.includes('.claude')
      );
      expect(claudeExfil).toBeDefined();
      expect(claudeExfil?.severity).toBe('high');
    });
    
    it('should detect network calls in hooks', () => {
      const result = scan({
        path: path.join(__dirname, 'fixtures/risks/suspicious-hook.sh'),
        json: false,
        verbose: false
      });
      
      const networkCall = result.findings.find(f => 
        f.message.includes('Network call')
      );
      expect(networkCall).toBeDefined();
    });
  });
  
  describe('Config Checking', () => {
    it('should detect helpers without models', () => {
      const result = scan({
        path: path.join(__dirname, 'fixtures/configs/.claude/config.json'),
        json: false,
        verbose: false
      });
      
      const noModel = result.findings.find(f => 
        f.message.includes('Helper') && f.message.includes('no model')
      );
      expect(noModel).toBeDefined();
      expect(noModel?.severity).toBe('medium');
    });
    
    it('should detect subagents without models', () => {
      const result = scan({
        path: path.join(__dirname, 'fixtures/configs/.claude/config.json'),
        json: false,
        verbose: false
      });
      
      const noModel = result.findings.find(f => 
        f.message.includes('Subagent') && f.message.includes('no model')
      );
      expect(noModel).toBeDefined();
    });
    
    it('should detect reviewers without models', () => {
      const result = scan({
        path: path.join(__dirname, 'fixtures/configs/.claude/config.json'),
        json: false,
        verbose: false
      });
      
      const noModel = result.findings.find(f => 
        f.message.includes('reviewer') && f.message.includes('no model')
      );
      expect(noModel).toBeDefined();
    });
    
    it('should flag model switching', () => {
      const result = scan({
        path: path.join(__dirname, 'fixtures/configs/.claude/config.json'),
        json: false,
        verbose: false
      });
      
      const switching = result.findings.find(f => 
        f.message.includes('Multiple different models')
      );
      expect(switching).toBeDefined();
    });
    
    it('should flag expensive models', () => {
      const result = scan({
        path: path.join(__dirname, 'fixtures/configs/.claude/config.json'),
        json: false,
        verbose: false
      });
      
      const expensive = result.findings.find(f => 
        f.message.includes('expensive models')
      );
      expect(expensive).toBeDefined();
    });
    
    it('should flag large context windows', () => {
      const result = scan({
        path: path.join(__dirname, 'fixtures/configs/.claude/config.json'),
        json: false,
        verbose: false
      });
      
      const largeContext = result.findings.find(f => 
        f.message.includes('large context')
      );
      expect(largeContext).toBeDefined();
    });
    
    it('should detect Cursor hooks that fail open', () => {
      const result = scan({
        path: path.join(__dirname, 'fixtures/configs/.cursor/hooks.json'),
        json: false,
        verbose: false
      });
      
      const failOpen = result.findings.find(f => 
        f.message.includes('fails open')
      );
      expect(failOpen).toBeDefined();
      expect(failOpen?.severity).toBe('high');
    });
    
    it('should detect user-level hooks', () => {
      const result = scan({
        path: path.join(__dirname, 'fixtures/configs/.cursor/hooks.json'),
        json: false,
        verbose: false
      });
      
      const userLevel = result.findings.filter(f => 
        f.message.includes('user-level scope')
      );
      expect(userLevel.length).toBeGreaterThan(0);
    });
  });
  
  describe('Clean Files', () => {
    it('should not flag clean configuration', () => {
      const result = scan({
        path: path.join(__dirname, 'fixtures/clean'),
        json: false,
        verbose: false
      });
      
      expect(result.highSeverityCount).toBe(0);
      expect(result.mediumSeverityCount).toBe(0);
    });
  });
  
  describe('Exit Codes', () => {
    it('should return non-zero findings count for problematic files', () => {
      const result = scan({
        path: path.join(__dirname, 'fixtures/secrets'),
        json: false,
        verbose: false
      });
      
      expect(result.highSeverityCount).toBeGreaterThan(0);
    });
  });
});
