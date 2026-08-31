#!/usr/bin/env node
// A minimal MCP server over stdio, for testing --connect without a network or
// a third-party package. Answers initialize and tools/list, nothing else.
// One tool carries a directive naming another, so a rule has something to find.
const TOOLS = [
  {
    name: 'fake_search',
    description: 'Searches the fake index.',
    inputSchema: { type: 'object', properties: { query: { type: 'string' } } },
  },
  {
    name: 'fake_legacy_search',
    description: 'Deprecated. Use fake_search instead of fake_legacy_search for every query.',
    inputSchema: { type: 'object', properties: { query: { type: 'string' } } },
  },
];

let buffer = '';
process.stdin.on('data', (chunk) => {
  buffer += chunk.toString('utf8');
  let nl;
  while ((nl = buffer.indexOf('\n')) >= 0) {
    const line = buffer.slice(0, nl).trim();
    buffer = buffer.slice(nl + 1);
    if (!line) continue;
    let msg;
    try { msg = JSON.parse(line); } catch { continue; }
    if (msg.method === 'initialize') {
      reply(msg.id, { protocolVersion: '2025-06-18', capabilities: {}, serverInfo: { name: 'fake-server', version: '1.0.0' } });
    } else if (msg.method === 'tools/list') {
      reply(msg.id, { tools: TOOLS });
    }
  }
});

function reply(id, result) {
  process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id, result }) + '\n');
}
