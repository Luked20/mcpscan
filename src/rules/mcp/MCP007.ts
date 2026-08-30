import type { PartialFinding, Rule, ServerDefinition } from '../../core/types.js';

/**
 * An exact version pin: `pkg@1.2.3`, optionally with a prerelease or build
 * suffix. Anchored on `@` preceded by a package-name character so an email
 * address or a scope prefix (`@scope/pkg`) is not mistaken for a pin.
 */
const EXACT_PIN = /[\w.-]@\d+\.\d+\.\d+(?:[-+][\w.-]+)?(?:\s|$)/;

/** Package managers that fetch and execute a package in one step. */
const FETCH_AND_RUN = /(?:^|\s)(?:npx|pnpm\s+dlx|bunx|uvx|pipx\s+run)(?:\s|$)/;

/** `curl … | sh`, `wget … | bash`, and the PowerShell equivalent. */
const PIPE_TO_SHELL = /\|\s*(?:sudo\s+)?(?:ba|z|k)?sh\b/;
const PIPE_TO_POWERSHELL = /\|\s*(?:iex|Invoke-Expression)\b/i;

function commandLine(server: ServerDefinition): string {
  return [server.command ?? '', ...(server.args ?? [])].join(' ').trim();
}

export const MCP007: Rule = {
  id: 'MCP007',
  title: 'Unpinned MCP server provenance',
  severity: 'medium',
  confidence: 'high',
  owasp: 'MCP04:2025 – Software Supply Chain Attacks & Dependency Tampering',
  appliesTo: 'server',
  check(server) {
    const findings: PartialFinding[] = [];
    const argv = commandLine(server);

    // 1. Fetched at run time with no exact version pin.
    if (FETCH_AND_RUN.test(argv) && !EXACT_PIN.test(argv)) {
      findings.push({
        location: server.loc(['args']),
        message:
          `Server "${server.name}" is started by fetching a package at run time with no exact ` +
          `version pin, so each run may download different code than the one you reviewed.`,
        remediation:
          'Pin the exact version (for example `package@1.4.2`), or install the package as a ' +
          'project dependency and point `command` at the local binary. Commit a lockfile so the ' +
          'transitive tree is pinned too.',
        evidence: argv.slice(0, 120),
      });
    }

    // 2. Downloaded straight into a shell.
    if (PIPE_TO_SHELL.test(argv) || PIPE_TO_POWERSHELL.test(argv)) {
      findings.push({
        location: server.loc(['command']),
        message:
          `Server "${server.name}" pipes downloaded content directly into a shell. Whatever the ` +
          `remote host serves at run time is executed, and it need not be what it served when you looked.`,
        remediation:
          'Download the script to a file, review it, pin it by commit SHA, and execute the verified ' +
          'copy. For releases, check the published checksum.',
        evidence: argv.slice(0, 120),
      });
    }

    // 3. Plaintext transport.
    if (server.url !== undefined && server.url.startsWith('http://')) {
      findings.push({
        location: server.loc(['url']),
        message:
          `Server "${server.name}" is reached over plaintext http://. Traffic and any bearer token ` +
          `sent with it are readable and modifiable in transit.`,
        remediation:
          'Use https://. If the server is local, prefer the stdio transport over HTTP entirely.',
        evidence: server.url.slice(0, 120),
      });
    }

    return findings;
  },
};
