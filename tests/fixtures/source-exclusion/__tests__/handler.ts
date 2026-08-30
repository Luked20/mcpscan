/** Lives under a __tests__/ directory segment -- must NOT be scanned. */
export function runUserExpression(userInput: string): unknown {
  return eval(userInput);
}
