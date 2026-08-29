import type { Rule } from '../core/types.js';
import { MCP001 } from './mcp/MCP001.js';
import { MCP002 } from './mcp/MCP002.js';
import { MCP003 } from './mcp/MCP003.js';
import { MCP004 } from './mcp/MCP004.js';
import { MCP005 } from './mcp/MCP005.js';
import { MCP007 } from './mcp/MCP007.js';
import { MCP009 } from './mcp/MCP009.js';
import { SKILL002 } from './skill/SKILL002.js';

export const RULES: Rule[] = [MCP001, MCP002, MCP003, MCP004, MCP005, MCP007, MCP009, SKILL002];
