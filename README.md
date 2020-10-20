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
- eliminates accidentally using JWTs unsafely, by constraining exposed methods to secure and declarative use cases

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

Tokens are typically passed to apis through the `Authorization` header, according to the [OAuth 2.0 Authorization Standard](https://tools.ietf.org/html/rfc6750), so this exposes an easy way to grab the token from there.

Alternatively, tokens may also be passed through an `Authorization` cookie, in the header. This is useful in browser environments where in order to protect users from XSS you store the JWT in an HTTPOnly cookie, inaccessible from JS. This method exposes an easy way to grab the token from an `authorization` cookie, with [two layer CSRF protection](#authorization-cookie).

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

_note: you can check whether your token was issued by an auth service that supports this OAuth2 Discovery Flow by checking whether the auth server exposes `Authorization Server Metadata` at expected address: `${token.iss}/.well-known/oauth-authorization-server`_

### `fn:getTokenFromHeaders({ token: string, issuer: string, audience: string | string[] })`

Use this function when you want to safely extract the token from the headers of the request made to your server.

This function supports two ways of extracting a token from headers:

- through the `Authorization` header
  - commonly used in native applications (iOS, Android, CLI, etc) where the user has programmatically accessible secure storage for their token
  - [OAuth 2.0 Authorization Standard](https://tools.ietf.org/html/rfc6750)
- through the `Authorization` cookie
  - commonly used in web applications, where users do not have programmatically accessible secure storage for their token, due to XSS, and must rely on HTTPOnly cookies instead

#### Authorization Header

Extracting the token from an authorization header is very simple. We simply look for a header with the name `Authorization` ([case insensitive, per spec](https://stackoverflow.com/a/5259004/3068233)) and get the token from it.

This function supports the authorization header defining the token with prefix of `Bearer` as well as not having a prefix at all:

- `Bearer __TOKEN__`
- `__TOKEN__`

#### Authorization Cookie

Extracting the token from an authorization cookie is simple, but requires protecting the user against cross-site-request-forgery (CSRF) attempts.

When a request is made with an authorization _header_, we know that the origin making the request has full programmatic access to the JWT, which confirms that the token owner intended to send the token. However, when a request is made with an authorization _cookie_, the origin making the request typically does not have programmatic access to the JWT at all. Instead, the browser simply sends the cookie to the target domain any time a request is made to that domain - leaving it susceptible to CSRF.

Cross-site-request-forgery (CSRF) is an attack that leverages the fact that browsers often do not consider the origin of a request when considering whether to send cookies. Specifically, if a user has a cookie from `yoursite.com`, visits `hakrsite.com`, and `hakrsite.com` sends a request to `yoursite.com` - the user's browser will happily send `yoursite.com` the user's cookie in the request that `hakrsite.com` made (e.g., `/transfer/funds?from=user&to=hakr&dollars=10000`). Without additional safeguards against CSRF, `yoursite.com` will see the cookie and authenticate the request.

This function, `getTokenFromHeaders`, leverages a two layer defence from the recommendations of [OWASP](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html):

1. [Verifying Origin with Standard Headers](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html#verifying-origin-with-standard-headers)
   - "Reliability on these headers comes from the fact that they cannot be altered programmatically (using JavaScript with an XSS vulnerability) as they fall under forbidden headers list, meaning that only the browser can set them"
2. [Synchronizer Token Based Mitigation](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html#token-based-mitigation)
   - "CSRF tokens prevent CSRF because without token, attacker cannot create a valid requests to the backend server."

This library leverages the properties of JWTs in order to make the implementation of origin-verification and anti-csrf-tokens seamless from the eyes of the implementer.

**Verifying Origin with Standard Headers**

In order to prevent a CSRF attack, we must make sure that only the intended source origin is making requests on behalf of our user. A secure way of doing so is by checking the `origin` and `referrer` headers.

[OWASP](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html#verifying-origin-with-standard-headers) explains the principle behind this approach well:

> "Reliability on these headers comes from the fact that they cannot be altered programmatically (using JavaScript with an XSS vulnerability) as they fall under forbidden headers list, meaning that only the browser can set them"

There are two parts to origin verification:

1. figuring out the target and source origins.
2. comparing the target and source origins.

Here are the details

1. figuring out the target and source origins

The `source origin` is easy to define and is explicitly defined in the OWASP recommendations. The `origin` and `referrer` headers are restricted headers, which mean that only browsers are allowed to set them. Therefore, we can trust that `sourceOrigin = header.origin ?? header.referrer`.

The `target origin` is figured out by leveraging the fact that the `aud` claim of a JWT should be the `uri` of the target origin that the token is intended to be consumed by. (i.e., `jwt.aud` should be the uri of the server that its intended for). Therefore, we are able to define that `targetOrigin = jwt.aud`.

2. comparing the target and source origins

In order to prevent a CSRF attack, we must verify that the source of the request is also the target of the request. In otherwords, we want to make sure that the source and target are the same site.

Special attention must be paid when considering whether `isSameSite(sourceOrigin, targetOrigin)` to the fact that some domains are actually public domains. For example, many websites are hosted on public domains such as `github.io` (github pages), `cloudfront.net` (aws's cdn), and etc. Fortunately, a standard [public domain list]() exists that we can use to consider this factor. Therefore, this library is able to realize that `yoursite.github.io` and `mysite.github.io` are _not_ the same site, while still understanding that `api.yoursite.com` and `www.yoursite.com` are the same site.

This library additionally takes the liberty of ignoring the `isSameSite` check cases where the `source origin` of a request is `localhost`. This is because there is no point in protecting a user from CSRF if they're making requests from a site hosted on their own machine. They either know what they're doing, or CSRF is the least of their concerns. (Note: this library _does_ still require the anti-csrf-token to be submitted for requests from `localhost`, however)

**Synchronizer Token Based Mitigation**

In order to prevent a CSRF attack, we must make sure that only the intended source origin is making requests on behalf of our user. An anti-csrf-token is the industry standard, best practice in doing so.

[OWASP](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html#verifying-origin-with-standard-headers) explains the principle behind this approach well:

> "CSRF tokens prevent CSRF because without token, attacker cannot create a valid requests to the backend server."

In a nutshell, an synchronizer anti-csrf-token is a unique, random value given to the user that can not be guessed, it is sent on each request to the server in the body or custom header, and can be verified on the server side.

There are several pieces that add up to make this a secure solution:

1. the anti-csrf-token can not be guessed or deduced

   - otherwise the attacker can guess or deduce this value as well

2. it is sent on each request in the body or custom header

   - meaning that the source of the request must have programmatic access to this `anti-csrf-token`

3. it can be verified on the server side

   - as if the server can't verify it, it wont know whether it is the correct token or a random value sent by an attacker

These pieces add together to guarantee that only the origin that was given the `anti-csrf-token` can send requests that are allowed to use the token in the cookie.

This library takes advantage of the unique properties of JWTs in order to make implementing an anti-csrf-token seamless. By using a `signature-redacted` version of the JWT that will be stored in the cookie as the anti-csrf-token, we are able to maintain a distributed, stateless approach to using a synchronizer anti-csrf-token.

Definition: signature-redacted meaning, the claims and header are not modified, but the signature is replaced with `__REDACTED__` so that the token can not be used for authentication.

Here is how this library addresses each part, specifically:

1. the anti-csrf-token can not be guessed or deduced

A JWT which has a unique, random `jti` claim on it can not be guessed or deduced. By requiring the endpoint that sets the JWT in the authorization cookie to also return a signature-redacted version of that JWT in the body of the response, we give the user an `anti-csrf-token` which can not be guessed or deduced.

The website that receives this `anti-csrf-token` is then able to safely store this anti-csrf-token in a browsers local-storage to be added to the header in subsequent requests, since the `anti-csrf-token` is a signature-redacted version of the full JWT and can not be authenticated.

Note: `getTokenFromHeaders` does check that the `anti-csrf-token`'s signature equals `__REDACTED__`, in order to guarantee that the `anti-csrf-token` could not possibly be used for authentication. It throws a `PotentialXSSVulnerabilityError` if this requirement is not met.

Note: `getTokenFromHeaders` does check that the JWT has a uuid for the `jti`, in order to guarantee that the `anti-csrf-token` is a unique and random value. It throws a `PotentialCSRFVulnerabilityError` if this requirement is not met.

2. it is sent on each request in the body or custom header

This library expects that the `anti-csrf-token` will be sent on the `Authorization` header of the request, to be found along with the authorization cookie which will be sent automatically by the user's browser.

Reusing the `authorization` header for the `anti-csrf-token` allows applications that store the jwt in a cookie and applications that store the jwt in directly in local storage to have the same exact code path, simplifying cross platform development.

3. it can be verified on the server side

When `getTokenFromHeaders` is called, it is able to verify that the `anti-csrf-token` is correct by checking that both the header and body of the tokens are the same.

By verifying that the `anti-csrf-token` synchronizes with the `jwt` and knowing that the `anti-csrf-token` is unique, random, and unguessable - we know that this request could only be made by the origin to which we gave the `jwt`.
