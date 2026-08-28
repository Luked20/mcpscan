#!/usr/bin/env node
import { Command } from 'commander';
import { writeFileSync } from 'node:fs';
import { scan } from '../scan.js';
import { formatPretty } from '../report/pretty.js';
import type { Severity } from '../core/types.js';

const program = new Command()
  .name('mcpscan')
  .argument('[path]', 'diretório ou arquivo para analisar', '.')
  .option('--format <fmt>', 'pretty | json | sarif | github')
  .option('--output <file>', 'escreve no arquivo em vez do stdout')
  .option('--fail-on <sev>', 'critical | high | medium | low | none', 'high')
  .option('--rules <ids>', 'roda só estas regras (separadas por vírgula)')
  .option('--disable <ids>', 'desliga estas regras (separadas por vírgula)')
  .option('--no-color', 'desativa cores');

program.parse();
const opts = program.opts();
const path = program.args[0] ?? '.';
const isTty = process.stdout.isTTY === true;
const format = opts['format'] ?? (isTty ? 'pretty' : 'json');

const result = await scan({
  path,
  failOn: opts['failOn'] as Severity | 'none',
  ...(opts['rules'] ? { rules: String(opts['rules']).split(',') } : {}),
  ...(opts['disable'] ? { disable: String(opts['disable']).split(',') } : {}),
});

if (result.error) {
  process.stderr.write(`mcpscan: ${result.error}\n`);
  process.exit(2);
}

const rendered = format === 'pretty'
  ? formatPretty(result.findings, { color: opts['color'] !== false && isTty, stats: result.stats })
  : JSON.stringify({ findings: result.findings, stats: result.stats }, null, 2);

if (opts['output']) writeFileSync(opts['output'], rendered);
else process.stdout.write(rendered + '\n');

process.exit(result.exitCode);
