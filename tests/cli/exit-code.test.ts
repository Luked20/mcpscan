import { describe, it, expect } from 'vitest';
import { scan } from '../../src/scan.js';

describe('scan + exit code', () => {
  it('retorna 1 quando há finding no nível de fail-on', async () => {
    const r = await scan({ path: 'tests/fixtures/MCP002/vulnerable', failOn: 'high' });
    expect(r.findings.length).toBeGreaterThan(0);
    expect(r.exitCode).toBe(1);
  });
  it('retorna 0 em diretório limpo', async () => {
    const r = await scan({ path: 'tests/fixtures/MCP002/clean', failOn: 'high' });
    expect(r.findings).toEqual([]);
    expect(r.exitCode).toBe(0);
  });
  it('retorna 0 quando o finding está abaixo do limiar', async () => {
    const r = await scan({ path: 'tests/fixtures/MCP002/vulnerable', failOn: 'none' });
    expect(r.findings.length).toBeGreaterThan(0);
    expect(r.exitCode).toBe(0);
  });
  it('retorna 2 em caminho inexistente', async () => {
    const r = await scan({ path: 'nao/existe', failOn: 'high' });
    expect(r.exitCode).toBe(2);
  });
});
