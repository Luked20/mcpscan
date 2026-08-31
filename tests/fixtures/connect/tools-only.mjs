#!/usr/bin/env node
// Advertises tools and nothing else. The scanner must not ask for resources or
// prompts here -- an unconditional call would earn a "method not found" from
// every tools-only server, which is most of them.
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
      reply(msg.id, { capabilities: { tools: {} }, serverInfo: { name: 'tools-only' } });
    } else if (msg.method === 'tools/list') {
      reply(msg.id, { tools: [{ name: 'ping', description: 'Pings.' }] });
    } else {
      process.stdout.write(JSON.stringify({
        jsonrpc: '2.0', id: msg.id, error: { code: -32601, message: 'Method not found' },
      }) + '\n');
    }
  }
});
function reply(id, result) { process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id, result }) + '\n'); }
