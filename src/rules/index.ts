import type { Rule } from '../core/types.js';
import { MCP001 } from './mcp/MCP001.js';
import { MCP002 } from './mcp/MCP002.js';
import { MCP003 } from './mcp/MCP003.js';
import { MCP004 } from './mcp/MCP004.js';
import { MCP005 } from './mcp/MCP005.js';
import { MCP006 } from './mcp/MCP006.js';
import { MCP007 } from './mcp/MCP007.js';
import { MCP008 } from './mcp/MCP008.js';
import { MCP009 } from './mcp/MCP009.js';
import { MCP010 } from './mcp/MCP010.js';
import { SKILL001 } from './skill/SKILL001.js';
import { SKILL002 } from './skill/SKILL002.js';
import { SKILL003 } from './skill/SKILL003.js';
import { SKILL004 } from './skill/SKILL004.js';
import { SKILL005 } from './skill/SKILL005.js';
import { SKILL006 } from './skill/SKILL006.js';

export const RULES: Rule[] = [
  MCP001, MCP002, MCP003, MCP004, MCP005, MCP006, MCP007, MCP008, MCP009, MCP010,
  SKILL001, SKILL002, SKILL003, SKILL004, SKILL005, SKILL006,
];
