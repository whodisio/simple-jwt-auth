import { redactSignature } from './redactSignature';

/**
 * check whether the token signature is redacted
 */
export const isRedactedSignatureToken = (token: string) => redactSignature({ token }) === token; // its already redacted if there is no change when redacting
