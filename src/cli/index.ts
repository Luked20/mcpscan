import { Command } from 'commander';
import { writeFileSync } from 'node:fs';
import { scan } from '../scan.js';
import { formatPretty } from '../report/pretty.js';
import { formatSarif } from '../report/sarif.js';
import { formatGithub } from '../report/github.js';
import { validateFormat } from '../report/format.js';
import { RULES } from '../rules/index.js';
import type { Severity } from '../core/types.js';
// Read at build time by esbuild/tsup (a JSON import is resolved statically from
// the source file's path), not at runtime — survives bundling.
import pkg from '../../package.json' with { type: 'json' };

const program = new Command()
  .name('mcpscan')
  .argument('[path]', 'directory or file to scan', '.')
  .option('--format <fmt>', 'pretty | json | sarif | github')
  .option('--output <file>', 'write to a file instead of stdout')
  .option('--fail-on <sev>', 'critical | high | medium | low | none', 'high')
  .option('--rules <ids>', 'run only these rules (comma-separated)')
  .option('--disable <ids>', 'turn off these rules (comma-separated)')
  .option('--no-color', 'disable colors');

program.parse();
const opts = program.opts();
const path = program.args[0] ?? '.';
const isTty = process.stdout.isTTY === true;
const format = opts['format'] ?? (isTty ? 'pretty' : 'json');

const formatError = validateFormat(format);
if (formatError) {
  process.stderr.write(`mcpscan: ${formatError}\n`);
  // No process.exit(): it can truncate stdout when it's a pipe.
  process.exitCode = 2;
} else {
  const result = await scan({
    path,
    failOn: opts['failOn'] as Severity | 'none',
    ...(opts['rules'] ? { rules: String(opts['rules']).split(',') } : {}),
    ...(opts['disable'] ? { disable: String(opts['disable']).split(',') } : {}),
  });

  // The error goes to stderr, but the report is still emitted: with a broken
  // rule, the findings already collected are still worth a partial report.
  if (result.error) process.stderr.write(`mcpscan: ${result.error}\n`);

  const rendered = format === 'pretty'
    ? formatPretty(result.findings, {
        color: opts['color'] !== false && isTty,
        stats: result.stats,
        ...(result.error !== undefined ? { error: result.error } : {}),
      })
    : format === 'sarif'
    ? formatSarif(result.findings, RULES, pkg.version, {
        executionSuccessful: result.exitCode !== 2,
        ...(result.error !== undefined ? { error: result.error } : {}),
      })
    : format === 'github'
    ? formatGithub(result.findings)
    : JSON.stringify({
        findings: result.findings,
        stats: result.stats,
        ...(result.error !== undefined ? { error: result.error } : {}),
      }, null, 2);

  if (opts['output']) writeFileSync(opts['output'], rendered);
  else process.stdout.write(rendered + '\n');

  process.exitCode = result.exitCode;
}
