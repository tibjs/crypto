export function assert(
  condition: any,
  msg = 'no additional info provided',
): asserts condition {
  if (!condition) {
    const err = new Error('Assertion Error: ' + msg);

    if (Error.captureStackTrace) Error.captureStackTrace(err, assert);

    throw err;
  }
}
