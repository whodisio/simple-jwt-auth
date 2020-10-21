import { SimpleJwtAuthError } from '../SimpleJwtAuthError';

export class PotentialCSRFAttackError extends SimpleJwtAuthError {
  constructor({ reason }: { reason: string }) {
    const message = `
Potential cross-site-request-forgery attack detected!!! ${reason}
    `.trim();
    super(message);
  }
}
