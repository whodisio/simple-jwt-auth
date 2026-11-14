import { MalfunctionError } from 'helpful-errors';

/**
 * .what = the class and message a call throws, as plain data
 * .why = a snapshot of the pair shows a reviewer the text a consumer meets; a call that does not throw fails loud
 */
export const getThrownOfCall = (input: {
  call: () => unknown;
}): { name: string; message: string } => {
  try {
    input.call();
  } catch (error) {
    if (!(error instanceof Error)) throw error;
    return { name: error.constructor.name, message: error.message };
  }
  throw new MalfunctionError('expected the call to throw, it returned', {
    call: input.call.toString(),
    hint: 'the guard under test no longer throws on this input; check whether the guard was removed or the input became valid',
  });
};
