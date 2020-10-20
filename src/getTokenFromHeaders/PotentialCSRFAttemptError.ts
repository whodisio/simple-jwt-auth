import { SimpleJwtAuthError } from '../SimpleJwtAuthError';

export class PotentialCSRFAttemptError extends SimpleJwtAuthError {
  constructor({ reason }: { reason: string }) {
    const message = `
Potential cross-site-request-forgery attempt detected!!! ${reason}
    `.trim();
    super(message);
  }
}
