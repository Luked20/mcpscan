import type { Rule } from '../core/types.js';
import { MCP002 } from './mcp/MCP002.js';

export const RULES: Rule<never>[] = [MCP002 as Rule<never>];
