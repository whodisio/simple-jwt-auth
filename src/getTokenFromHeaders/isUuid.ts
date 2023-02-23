/**
 * checks if a string is a uuid
 *
 * https://stackoverflow.com/a/13653180/3068233
 */
export const isUuid = (str: string) =>
  new RegExp(
    /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i,
  ).test(str);
