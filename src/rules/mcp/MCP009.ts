import type { PartialFinding, Rule } from '../../core/types.js';

/** Credential shapes with a distinctive, low-collision prefix. */
const CREDENTIALS: Array<[label: string, pattern: RegExp]> = [
  ['an Anthropic API key', /\bsk-ant-[A-Za-z0-9_-]{20,}/],
  ['an OpenAI API key', /\bsk-(?!ant-)[A-Za-z0-9_-]{20,}/],
  ['a GitHub token', /\bgh[pousr]_[A-Za-z0-9]{36,}/],
  ['an AWS access key id', /\bAKIA[0-9A-Z]{16}\b/],
  ['a Slack token', /\bxox[baprs]-[A-Za-z0-9-]{10,}/],
  ['a JSON Web Token', /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/],
];

/**
 * `${VAR}`, `$VAR`, `${env:VAR}` — the correct pattern, not the bug.
 * A value that is entirely a reference is never a hardcoded secret.
 */
const ENV_REFERENCE = /^\$\{?(?:env:)?[A-Za-z_][A-Za-z0-9_]*\}?$/;

/** Obvious fill-me-in values that happen to match a credential shape. */
const PLACEHOLDER = /^(?:x+|y+|your[-_ ]?\w*|<[^>]*>|changeme|todo|replace[-_ ]?me|example|dummy|placeholder)$/i;

/**
 * Show enough to identify which credential, never enough to use it. A finding
 * travels into CI logs, terminal scrollback, and the SARIF artifact that often
 * gets committed — a scanner that echoes the secret has copied it to three new
 * places and made the problem worse.
 */
function redact(value: string): string {
  return value.length <= 8 ? '***' : `${value.slice(0, 4)}…${value.slice(-2)}`;
}

export const MCP009: Rule = {
  id: 'MCP009',
  title: 'Credential hardcoded in MCP server configuration',
  severity: 'high',
  confidence: 'high',
  owasp: 'MCP01:2025 – Token Mismanagement & Secret Exposure',
  appliesTo: 'server',
  check(server) {
    const findings: PartialFinding[] = [];

    for (const [key, rawValue] of Object.entries(server.env ?? {})) {
      const value = rawValue.trim();
      if (value === '' || ENV_REFERENCE.test(value) || PLACEHOLDER.test(value)) continue;

      const hit = CREDENTIALS.find(([, pattern]) => pattern.test(value));
      if (!hit) continue;

      findings.push({
        location: server.loc(`${server.origin.jsonPath}.env.${key}`),
        message:
          `The \`${key}\` environment value of server "${server.name}" looks like ${hit[0]} ` +
          `written literally into the config file.`,
        remediation:
          `Replace the value with a reference such as \`\${${key}}\` and supply the secret from the ` +
          `environment or a secret manager. Then revoke and reissue this credential — moving it now ` +
          `does not remove it from the repository's git history, where it has been readable since ` +
          `the commit that introduced it.`,
        evidence: `${key}=${redact(value)}`,
      });
    }

    return findings;
  },
};
