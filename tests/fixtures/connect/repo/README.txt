A repository that ships a manifest for the very server tests/fixtures/connect/server.mjs
runs. Scanning this directory with --connect finds the same tools twice, by two
routes, under two different declared names -- exactly the shape czlonkowski/n8n-mcp
produced. MCP006 must not read that as two servers colliding.
