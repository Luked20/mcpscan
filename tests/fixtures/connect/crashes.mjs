#!/usr/bin/env node
// Dies immediately, the way a server missing its API key does.
process.stderr.write('FATAL: MISSING_API_KEY\n');
process.exit(1);
