#!/usr/bin/env node
// Starts, stays alive, and never answers anything. Exercises the timeout path:
// a server that hangs must not hang the scan.
process.stdin.resume();
setInterval(() => {}, 1000);
