#!/usr/bin/env node
import { Command } from 'commander';
import { writeFileSync } from 'node:fs';
import { scan } from '../scan.js';
import { formatPretty } from '../report/pretty.js';
import { formatSarif } from '../report/sarif.js';
import { formatGithub } from '../report/github.js';
import { validateFormat } from '../report/format.js';
import { RULES } from '../rules/index.js';
import type { Severity } from '../core/types.js';
// Lido em tempo de build pelo esbuild/tsup (JSON import é resolvido estaticamente
// pelo caminho do arquivo-fonte), não em tempo de execução — sobrevive ao bundling.
import pkg from '../../package.json' with { type: 'json' };

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

const formatError = validateFormat(format);
if (formatError) {
  process.stderr.write(`mcpscan: ${formatError}\n`);
  // Sem process.exit(): ele pode truncar o stdout quando é um pipe.
  process.exitCode = 2;
} else {
  const result = await scan({
    path,
    failOn: opts['failOn'] as Severity | 'none',
    ...(opts['rules'] ? { rules: String(opts['rules']).split(',') } : {}),
    ...(opts['disable'] ? { disable: String(opts['disable']).split(',') } : {}),
  });

  // O erro vai para o stderr, mas o relatório continua sendo emitido: com uma regra
  // quebrada os findings já coletados valem um relatório parcial.
  if (result.error) process.stderr.write(`mcpscan: ${result.error}\n`);

  const rendered = format === 'pretty'
    ? formatPretty(result.findings, {
        color: opts['color'] !== false && isTty,
        stats: result.stats,
        ...(result.error !== undefined ? { error: result.error } : {}),
      })
    : format === 'sarif'
    ? formatSarif(result.findings, RULES, pkg.version)
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
