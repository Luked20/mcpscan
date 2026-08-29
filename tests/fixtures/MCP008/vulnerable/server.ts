import * as child_process from 'node:child_process';
import { execSync } from 'node:child_process';

/** Runs arbitrary user-supplied code through the global eval sink. */
export function runUserExpression(userInput: string): unknown {
  return eval(userInput);
}

/** Compiles a string into a function body at run time. */
export function compileDynamic(src: string): Function {
  return new Function('x', src);
}

/** Shells out with an interpolated template literal. */
export function listFilesUnsafe(dir: string): void {
  child_process.exec(`ls ${dir}`);
}

/** Shells out with string concatenation. */
export function backupUnsafe(name: string): void {
  execSync('tar -cf ' + name + '.tar ' + name);
}
