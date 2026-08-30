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

/**
 * Docker flags that consume the next token. Needed because the image reference
 * is "the first argument after `run` that is not a flag or a flag's value", and
 * without knowing which flags take a value, `--mount type=bind,...` would make
 * `type=bind,...` look like the image.
 *
 * The list is not exhaustive and does not need to be: an unknown value-taking
 * flag makes its value the image candidate, and `looksLikeImage` then rejects
 * it. The failure mode is a miss, not a wrong finding.
 */
const DOCKER_VALUE_FLAGS = new Set([
  '-v', '--volume', '-e', '--env', '--env-file', '--mount', '-p', '--publish',
  '--name', '-w', '--workdir', '-u', '--user', '--network', '--entrypoint',
  '-l', '--label', '--add-host', '--device', '--platform', '--pull',
]);

/**
 * A Docker image reference: `name`, `owner/name`, `registry.io/owner/name`,
 * with an optional `:tag` and/or `@sha256:` digest.
 *
 * Deliberately strict, because this is what stands between the flag-walking
 * above and a wrong answer: a mount spec contains `=`, a bind path starts with
 * `/` or a drive letter, and neither can be an image.
 */
function looksLikeImage(token: string): boolean {
  if (token.includes('=') || token.startsWith('/') || token.startsWith('.')) return false;
  if (/^[A-Za-z]:[\\/]/.test(token)) return false; // a Windows path
  return /^[a-z0-9][a-z0-9._-]*(?:\/[a-z0-9][a-z0-9._-]*)*(?::[\w][\w.-]*)?(?:@sha256:[a-f0-9]{64})?$/i
    .test(token);
}

/**
 * The image `docker run` would pull, or `undefined` when this is not a
 * `docker run` at all (or the image could not be identified).
 *
 * Tokens come from `server.args` when it exists, because the config already
 * split them — re-splitting a joined string would break on a mount spec
 * containing a space. Falling back to splitting `command` covers the shape
 * where the whole invocation is written as one string.
 */
function dockerImage(server: ServerDefinition): string | undefined {
  const tokens = server.args !== undefined && server.args.length > 0
    ? [...(server.command !== undefined ? server.command.split(/\s+/) : []), ...server.args]
    : commandLine(server).split(/\s+/);

  const dockerAt = tokens.findIndex((t) => t === 'docker' || t.endsWith('/docker') || t.endsWith('\\docker.exe'));
  if (dockerAt < 0) return undefined;

  // `docker run`, not `docker build` / `docker compose` / anything else.
  let i = dockerAt + 1;
  while (i < tokens.length && tokens[i]!.startsWith('-')) i += 1; // global flags
  if (tokens[i] !== 'run') return undefined;
  i += 1;

  for (; i < tokens.length; i++) {
    const token = tokens[i]!;
    if (token.startsWith('-')) {
      // `--mount=x` carries its value inline; `--mount x` consumes the next token.
      if (!token.includes('=') && DOCKER_VALUE_FLAGS.has(token)) i += 1;
      continue;
    }
    return looksLikeImage(token) ? token : undefined;
  }
  return undefined;
}

/**
 * An image is pinned by a digest, or by any tag other than `latest`.
 *
 * A tag is technically mutable — it can be re-pushed — so this is the same
 * judgement the npm side of this rule already makes about `pkg@1.2.3`: an
 * explicit version is treated as a pin, because demanding a digest would fire
 * on essentially every install instruction ever written and stop being a
 * signal. No tag at all means `:latest`, which is the case worth reporting.
 */
function isPinnedImage(image: string): boolean {
  if (image.includes('@sha256:')) return true;
  const tag = image.split('/').pop()!.split(':')[1];
  return tag !== undefined && tag !== 'latest';
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

    // 1b. Pulled by Docker with no tag, or with `:latest`.
    const image = dockerImage(server);
    if (image !== undefined && !isPinnedImage(image)) {
      findings.push({
        location: server.loc(['args']),
        message:
          `Server "${server.name}" runs the Docker image \`${image}\`, which carries ` +
          `${image.includes(':') ? 'the `latest` tag' : 'no tag (so Docker resolves `:latest`)'}. ` +
          `Each start may pull a different image than the one you reviewed.`,
        remediation:
          'Pin the image to a version tag (`mcp/filesystem:1.4.2`) or, for a guarantee a tag cannot ' +
          'give, to a digest (`mcp/filesystem@sha256:…`).',
        evidence: image,
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
