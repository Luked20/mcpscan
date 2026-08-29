import { execFile, spawn } from 'node:child_process';
import * as child_process from 'node:child_process';

/** execFile with an argument array, not a shell string. Not this rule's concern. */
export function listFilesSafe(dir: string): void {
  execFile('ls', [dir]);
}

/** spawn with an argument array, not a shell string. */
export function statusSafe(): void {
  spawn('git', ['status']);
}

/** A constant string literal, not a template literal or concatenation. */
export function checkoutSafe(): void {
  child_process.exec('git status');
}

/** The word "eval" as part of a longer identifier, not the global eval sink. */
function evaluate(expression: string): number {
  return Number(expression);
}

/** Same idea: "eval" embedded in a longer identifier. */
function myEval(x: number): number {
  return x * 2;
}

/** A property named "eval" on an object, reached only through a dot -- not the global eval sink. */
interface Sandbox {
  eval: (code: string) => void;
}
declare const sandbox: Sandbox;

export function useSandbox(code: string): void {
  sandbox.eval(code);
}

export { evaluate, myEval };
