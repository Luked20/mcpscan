import { describe, it, expect } from 'vitest';
import { collectMcpConfig } from '../../src/collect/mcp-config.js';
import { MCP009 } from '../../src/rules/mcp/MCP009.js';
import type { ScanContext, ServerDefinition } from '../../src/core/types.js';

const ctx = {} as ScanContext;

/** Obviously fake, correctly shaped. Never commit anything that looks live. */
const FAKE = {
  github: `ghp_${'A'.repeat(36)}`,
  openai: `sk-${'A'.repeat(32)}`,
  anthropic: `sk-ant-${'A'.repeat(32)}`,
  aws: `AKIA${'B'.repeat(16)}`,
  slack: `xoxb-${'1'.repeat(12)}-${'2'.repeat(12)}`,
  jwt: `eyJ${'a'.repeat(20)}.${'b'.repeat(20)}.${'c'.repeat(20)}`,
};

function server(env: Record<string, string>): ServerDefinition {
  const text = JSON.stringify({ mcpServers: { s: { command: 'node', args: ['./s.js'], env } } }, null, 2);
  const [s] = collectMcpConfig('.mcp.json', text);
  if (!s) throw new Error('fixture did not produce a server');
  return s;
}

const run = (env: Record<string, string>) => MCP009.check(server(env) as never, ctx);

describe('MCP009 — detects credential shapes', () => {
  it.each(Object.entries(FAKE))('fires on %s', (key, value) => {
    expect(run({ [`${key.toUpperCase()}_TOKEN`]: value })).toHaveLength(1);
  });

  it('reports one finding per offending env entry', () => {
    expect(run({ A: FAKE.github, B: FAKE.openai, C: 'debug' })).toHaveLength(2);
  });

  it('distinguishes an Anthropic key from an OpenAI key', () => {
    expect(run({ K: FAKE.anthropic })[0]!.message).toContain('Anthropic');
    expect(run({ K: FAKE.openai })[0]!.message).toContain('OpenAI');
  });
});

describe('MCP009 — does not fire on the correct pattern', () => {
  it.each([
    ['${VAR} reference', '${GITHUB_TOKEN}'],
    ['$VAR reference', '$GITHUB_TOKEN'],
    ['${env:VAR} reference', '${env:TOKEN}'],
    ['placeholder your-token-here', 'your-token-here'],
    ['placeholder <YOUR_KEY>', '<YOUR_KEY>'],
    ['placeholder changeme', 'changeme'],
    ['placeholder xxx', 'xxx'],
    ['an empty value', ''],
    ['an ordinary setting', 'debug'],
    ['a port number', '8080'],
    ['a region', 'us-east-1'],
    ['a plain word starting with sk', 'skip'],
  ])('does not fire on %s', (_label, value) => {
    expect(run({ TOKEN: value })).toEqual([]);
  });
});

describe('MCP009 — the finding must never leak the secret', () => {
  it.each(Object.entries(FAKE))('redacts %s everywhere in the finding', (_key, value) => {
    const [f] = run({ TOKEN: value });
    expect(f).toBeDefined();
    const wholeFinding = JSON.stringify(f);
    expect(wholeFinding).not.toContain(value);
    expect(f!.message).not.toContain(value);
    expect(f!.remediation).not.toContain(value);
    expect(f!.evidence ?? '').not.toContain(value);
  });

  it('shows enough to identify which value, and no more', () => {
    const [f] = run({ GITHUB_TOKEN: FAKE.github });
    expect(f!.evidence).toContain('GITHUB_TOKEN=');
    expect(f!.evidence).toContain('ghp_');
    expect((f!.evidence ?? '').length).toBeLessThan(40);
  });
});

describe('MCP009 — remediation', () => {
  it('tells the user to revoke, not merely to move the value', () => {
    const [f] = run({ GITHUB_TOKEN: FAKE.github });
    expect(f!.remediation.toLowerCase()).toContain('revoke');
    expect(f!.remediation.toLowerCase()).toContain('git history');
  });

  it('names the env key in the suggested replacement', () => {
    const [f] = run({ GITHUB_TOKEN: FAKE.github });
    expect(f!.remediation).toContain('${GITHUB_TOKEN}');
  });
});

describe('MCP009 — shape', () => {
  it('returns nothing when there is no env block', () => {
    const text = JSON.stringify({ mcpServers: { s: { command: 'node' } } }, null, 2);
    const [s] = collectMcpConfig('.mcp.json', text);
    expect(MCP009.check(s! as never, ctx)).toEqual([]);
  });

  it('locates the finding at the offending env key', () => {
    const [f] = run({ GITHUB_TOKEN: FAKE.github });
    expect(f!.location.jsonPath).toBe('mcpServers.s.env.GITHUB_TOKEN');
  });
});

describe('MCP009 — credentials outside env', () => {
  // Until this existed the rule looked only in `env` -- the one place a careful
  // author already gets right. The tavily config in the regression corpus puts
  // its key in `command`, as `?tavilyApiKey=…`.
  const build = (entry: Record<string, unknown>): ServerDefinition => {
    const text = JSON.stringify({ mcpServers: { s: entry } }, null, 2);
    const [s] = collectMcpConfig('.mcp.json', text);
    if (!s) throw new Error('fixture did not produce a server');
    return s;
  };
  const check = (entry: Record<string, unknown>) => MCP009.check(build(entry) as never, ctx);

  it('flags a key in a remote server URL', () => {
    const findings = check({ url: `https://mcp.example.com/mcp?apiKey=${FAKE.openai}` });
    expect(findings).toHaveLength(1);
    expect(findings[0]!.location.jsonPath).toBe('mcpServers.s.url');
  });

  it('flags a key inside the command string', () => {
    const findings = check({ command: `npx -y mcp-remote https://x.dev/mcp?key=${FAKE.anthropic}` });
    expect(findings).toHaveLength(1);
    expect(findings[0]!.location.jsonPath).toBe('mcpServers.s.command');
  });

  it('flags a key passed as an argument, and points at that argument', () => {
    const findings = check({ command: 'node', args: ['./s.js', '--token', FAKE.github] });
    expect(findings).toHaveLength(1);
    expect(findings[0]!.location.jsonPath).toBe('mcpServers.s.args[2]');
  });

  it('redacts the credential everywhere it reports one', () => {
    for (const entry of [
      { url: `https://x.dev/mcp?key=${FAKE.openai}` },
      { command: 'node', args: [FAKE.openai] },
    ]) {
      const evidence = check(entry)[0]!.evidence!;
      expect(evidence).not.toContain(FAKE.openai);
      expect(evidence).toContain('…');
    }
  });

  it.each([
    ['a placeholder', 'https://mcp.tavily.com/mcp/?tavilyApiKey=<your-api-key>'],
    ['an env reference', 'https://mcp.example.com/mcp?key=${TAVILY_KEY}'],
    ['no credential at all', 'https://mcp.example.com/mcp'],
  ])('does NOT flag %s in a URL', (_label, url) => {
    expect(check({ url })).toEqual([]);
  });

  it('does NOT flag an ordinary command line', () => {
    expect(check({ command: 'uvx', args: ['awslabs.mysql-mcp-server@latest'] })).toEqual([]);
  });

  it('reports env, url and args independently', () => {
    const findings = check({
      command: 'node',
      args: [FAKE.github],
      env: { OPENAI_API_KEY: FAKE.openai },
    });
    expect(findings).toHaveLength(2);
  });
});
