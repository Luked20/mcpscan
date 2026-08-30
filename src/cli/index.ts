import { Command } from 'commander';
import { readFileSync, writeFileSync } from 'node:fs';
import { scan } from '../scan.js';
import { formatPretty } from '../report/pretty.js';
import { formatSarif } from '../report/sarif.js';
import { formatGithub } from '../report/github.js';
import { formatBaseline, parseBaseline } from '../report/baseline.js';
import { validateFormat } from '../report/format.js';
import { loadConfig, resolveOptions, DEFAULT_CONFIG_FILE } from '../config.js';
import { RULES } from '../rules/index.js';
import type { Severity } from '../core/types.js';
// Read at build time by esbuild/tsup (a JSON import is resolved statically from
// the source file's path), not at runtime — survives bundling.
import pkg from '../../package.json' with { type: 'json' };

const program = new Command()
  .name('mcpscan')
  .argument('[path]', 'directory or file to scan', '.')
  .option('--format <fmt>', 'pretty | json | sarif | github | baseline')
  .option('--output <file>', 'write to a file instead of stdout')
  // No commander defaults on the options a config file can also set: a default
  // applied here is indistinguishable from a value the user typed, and the
  // config would then lose to a flag nobody passed. Defaults are applied after
  // the merge in `main()` instead.
  .option('--fail-on <sev>', 'critical | high | medium | low | none (default: high)')
  .option('--rules <ids>', 'run only these rules (comma-separated)')
  .option('--disable <ids>', 'turn off these rules (comma-separated)')
  .option('--baseline <file>', 'ignore findings already listed in this file')
  .option('--config <file>', `config file (default: ${DEFAULT_CONFIG_FILE} if present)`)
  .option('--quiet', 'print findings only; nothing at all when a scan is clean')
  .option('--no-color', 'disable colors');

program.parse();
const opts = program.opts();
const path = program.args[0] ?? '.';
const isTty = process.stdout.isTTY === true;

/**
 * Everything that can stop the run before scanning is exit 2 — "could not
 * look", never "nothing found" (SPEC §9, §16.6). Returning the code rather
 * than calling `process.exit()`, which can truncate stdout when it is a pipe.
 */
function bail(message: string): 2 {
  process.stderr.write(`mcpscan: ${message}\n`);
  return 2;
}

async function main(): Promise<0 | 1 | 2> {
  const configFile = (opts['config'] as string | undefined) ?? DEFAULT_CONFIG_FILE;
  const config = loadConfig(configFile, opts['config'] !== undefined);
  if (typeof config === 'string') return bail(config);

  // Precedence — CLI flag > config file > built-in default — lives in
  // resolveOptions() so it can be tested without running the CLI.
  const resolved = resolveOptions(
    {
      ...(opts['format'] !== undefined ? { format: String(opts['format']) } : {}),
      ...(opts['failOn'] !== undefined ? { failOn: String(opts['failOn']) } : {}),
      ...(opts['rules'] !== undefined ? { rules: String(opts['rules']) } : {}),
      ...(opts['disable'] !== undefined ? { disable: String(opts['disable']) } : {}),
      ...(opts['baseline'] !== undefined ? { baseline: String(opts['baseline']) } : {}),
    },
    config,
    isTty,
  );
  const { format, rules, disable, baseline: baselineFile } = resolved;
  const failOn = resolved.failOn as Severity | 'none';

  const formatError = validateFormat(format);
  if (formatError) return bail(formatError);

  let baseline: Set<string> | undefined;
  if (baselineFile !== undefined) {
    // A baseline that fails to load must not degrade to "no baseline": that
    // turns every already-accepted finding back on at once, which reads as the
    // scanner having found new problems.
    let text: string;
    try {
      text = readFileSync(baselineFile, 'utf8');
    } catch (err) {
      return bail(`could not read baseline ${baselineFile}: ${(err as Error).message}`);
    }
    const parsed = parseBaseline(text, baselineFile);
    if (typeof parsed === 'string') return bail(parsed);
    baseline = parsed;
  }

  const result = await scan({
    path,
    failOn,
    ...(rules ? { rules } : {}),
    ...(disable ? { disable } : {}),
    ...(baseline ? { baseline } : {}),
  });

  // The error goes to stderr, but the report is still emitted: with a broken
  // rule, the findings already collected are still worth a partial report.
  if (result.error) process.stderr.write(`mcpscan: ${result.error}\n`);

  const rendered = format === 'pretty'
    ? formatPretty(result.findings, {
        color: opts['color'] !== false && isTty,
        stats: result.stats,
        ...(opts['quiet'] === true ? { quiet: true } : {}),
        ...(result.error !== undefined ? { error: result.error } : {}),
      })
    : format === 'sarif'
    ? formatSarif(result.findings, RULES, pkg.version, {
        executionSuccessful: result.exitCode !== 2,
        ...(result.error !== undefined ? { error: result.error } : {}),
      })
    : format === 'github'
    ? formatGithub(result.findings)
    : format === 'baseline'
    ? formatBaseline(result.findings)
    : JSON.stringify({
        findings: result.findings,
        stats: result.stats,
        ...(result.error !== undefined ? { error: result.error } : {}),
      }, null, 2);

  if (opts['output']) writeFileSync(opts['output'], rendered);
  // `--quiet` on a clean scan renders the empty string; printing a bare newline
  // for it would defeat the point.
  else if (rendered !== '') process.stdout.write(rendered + '\n');

  return result.exitCode;
}

process.exitCode = await main();
