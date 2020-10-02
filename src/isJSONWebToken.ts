const JWT_REGEXP = /^[a-zA-Z0-9\-_]+?\.[a-zA-Z0-9\-_]+?\.([a-zA-Z0-9\-_]+)?$/;

/**
 * check whether the string matches the shape of a JSON Web Token
 */
export const isJSONWebToken = (token: string) => new RegExp(JWT_REGEXP).test(token);
