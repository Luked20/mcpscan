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

const REMEDIATION =
  'Replace the literal with a reference such as `${API_KEY}` and supply the secret from the ' +
  'environment or a secret manager. Then revoke and reissue this credential — moving it now ' +
  "does not remove it from the repository's git history, where it has been readable since " +
  'the commit that introduced it.';

/**
 * Finds a credential embedded anywhere inside a longer string — a URL query
 * parameter, a `--api-key` argument.
 *
 * The `${VAR}` and placeholder guards the `env` path applies to a whole value
 * are neither possible nor needed here: what is checked is the matched
 * substring, and every pattern in `CREDENTIALS` requires a distinctive real
 * prefix (`sk-ant-`, `ghp_`, `AKIA`). `?key=<your-api-key>` and
 * `?key=${TAVILY_KEY}` match none of them, which is the right answer for both.
 */
function findEmbedded(text: string): { label: string; value: string } | undefined {
  for (const [label, pattern] of CREDENTIALS) {
    const m = pattern.exec(text);
    if (m) return { label, value: m[0] };
  }
  return undefined;
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
        location: server.loc(['env', key]),
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

    // `env` is the tidy place to put a secret, not the only one. A remote
    // server's key often rides in the URL's query string and a stdio server's
    // in an argument -- the tavily config in the regression corpus puts one in
    // `command` itself, as `?tavilyApiKey=…`. Checking only `env` meant looking
    // in the one place a careful author had already got right.
    if (server.url !== undefined) {
      const hit = findEmbedded(server.url);
      if (hit) {
        findings.push({
          location: server.loc(['url']),
          message:
            `The URL of server "${server.name}" carries ${hit.label} in it. A URL travels into ` +
            'client logs, proxy logs and error reports, so a credential in one leaks further than ' +
            'a config file alone does.',
          remediation: REMEDIATION,
          evidence: server.url.replace(hit.value, redact(hit.value)).slice(0, 120),
        });
      }
    }

    const argv: Array<{ path: (string | number)[]; label: string; text: string }> = [
      ...(server.command !== undefined ? [{ path: ['command'], label: 'command', text: server.command }] : []),
      ...(server.args ?? []).map((a, i) => ({ path: ['args', i], label: `argument ${i}`, text: a })),
    ];

    for (const { path, label, text } of argv) {
      const hit = findEmbedded(text);
      if (!hit) continue;
      findings.push({
        location: server.loc(path),
        message:
          `The ${label} of server "${server.name}" contains ${hit.label} written literally into ` +
          'the config file. A command line is also visible to every process on the machine that ' +
          'can read the process table.',
        remediation: REMEDIATION,
        evidence: text.replace(hit.value, redact(hit.value)).slice(0, 120),
      });
    }

    return findings;
  },
};
