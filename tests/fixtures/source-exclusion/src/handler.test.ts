/** Test file for handler.ts, matched by basename (*.test.ts) -- must NOT be scanned. */
export function runUserExpression(userInput: string): unknown {
  return eval(userInput);
}
