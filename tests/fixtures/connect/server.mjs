#!/usr/bin/env node
// A minimal MCP server over stdio, for testing --connect without a network or
// a third-party package. Answers initialize and tools/list, nothing else.
// `fake_read_file` gives a rule something to find (MCP004: an unconstrained
// path on a file tool). `fake_legacy_search` is the opposite case on purpose --
// a directive naming a tool of the *same* server, which MCP006 must not report,
// because that is documentation and not redirection.
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
  {
    name: 'fake_read_file',
    description: 'Reads a file from disk and returns its contents.',
    inputSchema: { type: 'object', properties: { path: { type: 'string' } }, required: ['path'] },
  },
];

// The other two primitives. `notes://{user_id}` is a resource *template*: its
// uri carries a placeholder a caller fills, which is the shape DVMCP challenge 1
// used to hide its whole vulnerability where no tool rule could see it.
const RESOURCES = [
  { uri: 'config://settings', name: 'settings', description: 'Server settings.', mimeType: 'application/json' },
];
const RESOURCE_TEMPLATES = [
  { uriTemplate: 'notes://{user_id}', name: 'notes', description: 'Notes for a user.' },
];
const PROMPTS = [
  {
    name: 'summarise',
    description: 'Summarise a document.',
    arguments: [{ name: 'document', description: 'The text to summarise.', required: true }],
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
      reply(msg.id, {
        protocolVersion: '2025-06-18',
        // Advertised, so the scanner asks for them. A server that does not
        // advertise is never asked -- see connect.ts.
        capabilities: { tools: {}, resources: {}, prompts: {} },
        serverInfo: { name: 'fake-server', version: '1.0.0' },
      });
    } else if (msg.method === 'tools/list') {
      reply(msg.id, { tools: TOOLS });
    } else if (msg.method === 'resources/list') {
      reply(msg.id, { resources: RESOURCES });
    } else if (msg.method === 'resources/templates/list') {
      reply(msg.id, { resourceTemplates: RESOURCE_TEMPLATES });
    } else if (msg.method === 'prompts/list') {
      reply(msg.id, { prompts: PROMPTS });
    }
  }
});

function reply(id, result) {
  process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id, result }) + '\n');
}
