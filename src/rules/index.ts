import type { Rule } from '../core/types.js';
import { MCP001 } from './mcp/MCP001.js';
import { MCP002 } from './mcp/MCP002.js';
import { MCP003 } from './mcp/MCP003.js';

export const RULES: Rule[] = [MCP001, MCP002, MCP003];
