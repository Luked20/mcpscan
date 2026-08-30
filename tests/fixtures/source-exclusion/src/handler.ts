/** Deployed tool handler -- this one must be scanned. */
export function runUserExpression(userInput: string): unknown {
  return eval(userInput);
}
