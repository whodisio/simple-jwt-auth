import { SimpleJwtAuthError } from '../SimpleJwtAuthError';

export class JwtAuthenticationError extends SimpleJwtAuthError {
  constructor({ reason }: { reason: string }) {
    const message = `
this JWT can not be trusted! ${reason}
    `.trim();
    super(message);
  }
}
