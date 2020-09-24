# simple-jwt-auth

![ci_on_commit](https://github.com/whodisio/simple-jwt-auth/workflows/ci_on_commit/badge.svg)
![deploy_on_tag](https://github.com/whodisio/simple-jwt-auth/workflows/deploy_on_tag/badge.svg)

A simple, convenient, and safe interface for interacting with JSON Web Tokens (JWTs) for authentication and authorization

Simple:

- exposes simple, declarative functions for each supported use case
- throws self explanatory errors when something goes wrong
- leverages open source standards to securely simplify the auth process
  - e.g., can automatically lookup the public key required to verify a JWT by using the [OAuth2 Discovery Flow](https://tools.ietf.org/id/draft-ietf-oauth-discovery-08.html)

Safe:

- enforces best practices of JWT authentication
- eliminates accidentally using JWTs unsafely, by only exposing methods that allow safe usage

---

References:

- [JSON Web Token (JWT)](https://tools.ietf.org/html/rfc7519)
- [JSON Web Signature (JWS)](https://www.rfc-editor.org/rfc/rfc7515.html)
- [OAuth 2.0 Authorization Server Metadata](https://tools.ietf.org/html/rfc8414)
- [JSON Web Key (JWK)](https://tools.ietf.org/html/rfc7517)
- [The OAuth 2.0 Authorization Framework: Bearer Token Usage](https://tools.ietf.org/html/rfc8414)
- [JSON Web Token Best Current Practices](https://tools.ietf.org/html/draft-ietf-oauth-jwt-bcp-07)

---

# Install

```sh
npm install --save simple-jwt-auth
```

# Example

### Authenticate and get claims from a JWT

This looks up the public key for the token and authenticates the claims. Useful any time you need to make sure that the claims are accurate (e.g., server side).

```ts
import { getAuthedClaims } from 'simple-jwt-auth';
const claims = getAuthedClaims({
  token: 'eyJhbGciOiJSUzI1NiIsInR...', // a jwt
  issuer: 'https://auth.whodis.io/...', // who you expect to have issued the token, must match `token.claims.iss`
  audience: 'ae7f50b0-c762-821...', // the audience the token should be for, must match `token.claims.aud`
});
```

As long as your token's issuer publishes [Authorization Server Metadata (an OAuth2 standard)](https://tools.ietf.org/html/rfc8414), we can find the public key for you and use it to authenticate your JWT.

### Get token from headers

This grabs the token from the standard bearer token header for you. Useful whenever you need to grab a token from an HTTP request.

```ts
import { getTokenFromHeaders } from 'simple-jwt-auth';
const token = getTokenFromHeaders({ headers });
```

Tokens are passed to apis through the `Authentication` header, according to the [OAuth 2.0 Authorization Standard](https://tools.ietf.org/html/rfc6750), so this exposes an easy way to grab the token from there.

### Get claims from a JWT without checking their authenticity

This simply decodes the body of the token and returns the claims, without checking anything. Useful for insecure environments (e.g., client side) where you cant trust data anyway - and debugging.

```ts
import { getUnauthedClaims } from 'simple-jwt-auth';
const claims = getUnauthedClaims({
  token: 'eyJhbGciOiJSUzI1NiIsInR...', // a jwt
});
```

### Create a secure distributed auth token

This method creates a JWT after checking that requirements for secure distributed authentication with the would be token are met.

```ts
import { createSecureDistributedAuthToken } from 'simple-jwt-auth';
const token = createSecureDistributedAuthToken({
  headerClaims: { alg: 'RS256', kid: '4.some_directory', typ: 'JWT' },
  claims: {
    iss: 'https://auth.whodis.io/...',
    aud: 'f7326c71-cf5a-4637-9580-8e83c2692e96',
    sub: 'e41ea57c-f630-45ba-88fc-8888b06c588e',
    exp: 2516239022,
  },
  privateKey, // rsa pem format private key string
});
```

# Docs

### `fn:getAuthedClaims({ token: string, issuer: string, audience: string | string[] })`

Use this function when you want to authenticate and get the claims that a token is making for use in your applications.

If your token's issuer publishes [Authorization Server Metadata (an OAuth2 standard)](https://tools.ietf.org/html/rfc8414), then we can find the public key for you. We'll cache it up to 5 min by default to speed up subsequent checks.

We check the authenticity of the token in the following ways:

- the token is valid
  - by verifying the signature
    - check that we can verify the signature comes from the issuer, with the public key
    - check that the header/payload have not been tampered with, with the signature
    - check that the token uses an asymmetric signing key, for secure decentralized authentication
  - by verifying the timestamps
    - token is not expired
    - token is not used before its allowed to be
- the token comes from the expected issuer
  - otherwise, anyone can issue claims to your server
- the token is meant for your application
  - otherwise, a token from the same issuer but for a different application could be used to access your application

References:

- https://tools.ietf.org/html/draft-ietf-oauth-jwt-bcp-07
- https://www.sjoerdlangkemper.nl/2016/09/28/attacking-jwt-authentication/
- https://www.cloudidentity.com/blog/2014/03/03/principles-of-token-validation/

Example:

```ts
import { getAuthedClaims } from 'simple-jwt-auth';
const claims = getAuthedClaims({
  /**
   * The JWT that you're checking for authenticity before getting claims
   */
  token,

  /**
   * Who you expect to issue the JWT.
   *
   * The issuer `string` that you define here is checked against the issuer that the token was issued by (`token.claims.iss`)
   *
   * This is required because it is critical for security that you only accept tokens from expected issuers.
   *
   * `getAuthedClaims` will throw an error if `issuer !== token.claims.iss`
   */
  issuer,

  /**
   * The id(s) that the JWT will use to specify that it was created for your application.
   *
   * The audience `string` (or each `string` in the `string[]`) that you define here is checked against the audience that the token is for (`token.claims.aud`).
   *
   * This is required, as it is critical for security that you only trust tokens that were intended for you
   *
   * `getAuthedClaims` will throw an error if `audience !== token.claims.aud`
   */
  audience,
});
```

**note: you can check whether your token was issued by an auth service that supports this OAuth2 Discovery Flow by checking whether the auth server exposes `Authorization Server Metadata` at expected address: `${token.iss}/.well-known/oauth-authorization-server`**
