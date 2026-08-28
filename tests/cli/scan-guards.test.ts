import { describe, it, expect } from 'vitest';
import { scan } from '../../src/scan.js';
import type { Severity } from '../../src/core/types.js';

const VULN = 'tests/fixtures/MCP002/vulnerable';

describe('seleção de regras', () => {
  it('ID desconhecido em --rules é exit 2, não scan silencioso', async () => {
    const r = await scan({ path: VULN, failOn: 'high', rules: ['MCP999'] });
    expect(r.exitCode).toBe(2);
    expect(r.error).toContain('MCP999');
    expect(r.error).toContain('MCP002'); // lista as válidas
  });

  it('ID desconhecido em --disable também é exit 2', async () => {
    const r = await scan({ path: VULN, failOn: 'high', disable: ['MCP02'] });
    expect(r.exitCode).toBe(2);
    expect(r.error).toContain('MCP02');
  });

  it('conjunto de regras vazio depois do filtro é exit 2', async () => {
    const r = await scan({ path: VULN, failOn: 'high', disable: ['MCP002'] });
    expect(r.exitCode).toBe(2);
    expect(r.error).toBeTruthy();
  });

  it('ID conhecido continua funcionando', async () => {
    const r = await scan({ path: VULN, failOn: 'high', rules: ['MCP002'] });
    expect(r.exitCode).toBe(1);
    expect(r.error).toBeUndefined();
  });
});

describe('nada para escanear', () => {
  it('zero subjects é exit 2, não tique verde', async () => {
    const r = await scan({ path: 'tests/fixtures/empty', failOn: 'high' });
    expect(r.exitCode).toBe(2);
    expect(r.error).toContain('tests/fixtures/empty');
  });

  it('stats separa arquivos examinados de arquivos com tools', async () => {
    const r = await scan({ path: VULN, failOn: 'high' });
    expect(r.stats).toEqual({ filesExamined: 1, filesWithTools: 1, tools: 1, skills: 0 });
  });
});

describe('--fail-on inválido', () => {
  it('valor fora do conjunto é exit 2', async () => {
    const r = await scan({ path: VULN, failOn: 'NONE' as Severity });
    expect(r.exitCode).toBe(2);
    expect(r.error).toContain('NONE');
  });

  it('não deixa o limiar aceitar tudo silenciosamente', async () => {
    const r = await scan({ path: VULN, failOn: 'NONE' as Severity });
    expect(r.exitCode).not.toBe(1);
    expect(r.exitCode).not.toBe(0);
  });
});
