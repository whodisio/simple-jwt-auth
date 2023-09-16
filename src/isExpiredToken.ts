import { getUnauthedClaims } from './getUnauthedClaims';

// define basic date manipulation fns (dont import from a third party lib to decrease bundle size; this stuff is really basic too)
export const fromUnixTime = (seconds: number) => new Date(seconds * 1000);
export const isBefore = (referenceDate: Date, comparisonDate: Date) =>
  referenceDate.getTime() < comparisonDate.getTime();
export const isAfter = (referenceDate: Date, comparisonDate: Date) =>
  referenceDate.getTime() > comparisonDate.getTime();

/**
 * check whether the token is expired
 */
export const isExpiredToken = (token: string) => {
  const now = new Date();
  const unauthedClaims = getUnauthedClaims({ token });
  return isAfter(now, fromUnixTime(unauthedClaims.exp));
};
