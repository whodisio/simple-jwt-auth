# simple-jwt-auth

A simple, convenient, and safe interface for using JSON Web Tokens (JWTs) for authentication and authorization

Simple:

- exposes simple, declarative functions for each supported use case
- throws self explanatory errors when something goes wrong
- leverages open source standards to securely simplify the auth process
  - e.g., can automatically lookup the public key required to verify a JWT by using the [OAuth2 Discovery Flow](https://tools.ietf.org/id/draft-ietf-oauth-discovery-08.html)

Safe:

- enforces best practices of JWT authentication
- eliminates accidentally using JWTs unsafely, by constraining exposed methods to secure and declarative use cases

In otherwords, it's built to provide [a pit of success](https://blog.codinghorror.com/falling-into-the-pit-of-success/)

---

# Background

JSON Web Token (JWT) authentication is a great way to implement authentication and authorization for user facing applications

Using JWTs to sign requests enables distributed and stateless auth which eliminates latency and reduces costs, for snappy user experiences at scale.
- the request-signature, the jwt, can be authenticated publicly, by anyone
  - [distributed] no api calls to issuer-server required, client-public-key is published at wellknown url, cacheable, static
  - [stateless] no state to manage, access, or upkeep for authenticating requests
- the request-signature, the jwt, identifies the requester and scope
  - [distributed] no api calls to issuer-server required, client identity is embedded and extractable from the request-signature
  - [stateless] no state to manage, access, or upkeep for identifying the requester

References:
- [JSON Web Token (JWT)](https://tools.ietf.org/html/rfc7519)
- [JSON Web Signature (JWS)](https://www.rfc-editor.org/rfc/rfc7515.html)
- [OAuth 2.0 Authorization Server Metadata](https://tools.ietf.org/html/rfc8414)
- [JSON Web Key (JWK)](https://tools.ietf.org/html/rfc7517)
- [The OAuth 2.0 Authorization Framework: Bearer Token Usage](https://tools.ietf.org/html/rfc8414)
- [JSON Web Token Best Current Practices](https://tools.ietf.org/html/draft-ietf-oauth-jwt-bcp-07)


Note: if you're looking to implement authentication and authorization for SDK applications, [HMAC Key Auth](https://github.com/whodisio/simple-hmackey-auth) may be a better fit due to their [less vulnerable](https://softwareengineering.stackexchange.com/a/444092/146747) nature

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

This library leverages the properties of JWTs in order to make the implementation of origin-verification and anti-csrf-tokens seamless from the eyes of the developer.

The first layer, `Verify Origin with Standard Headers`, is composed of two parts:

1. figuring out the `target origin` and `source origin`

   - `sourceOrigin = header.origin ?? header.referrer`, as defined by the OWASP recommendations
      - these can be trusted because they are restricted headers, which can only be set by browsers
      - `if (!sourceOrigin) throw new PotentialCSRFAttackError` - dont allow requests without either `origin` or `referrer` defined
   - `targetOrigin = jwt.aud`, i.e. the audience claim of the token
      - the `aud` claim of a JWT should be the `uri` of the target origin that the token is intended to be consumed by

2. comparing the `target origin` and `source origin`

   - `if (!isSameSite(sourceOrigin, targetOrigin)) throw new PotentialCSRFAttackError`
      - check that `isSameSite(sourceOrigin, targetOrigin)`
         - `api.yoursite.com` and `www.yoursite.com` are the same site, since they differ only by subdomain
         - `yoursite.github.io` and `mysite.github.io` are _not_ the same site, since domains like `github.io` and `cloudfront.net` are a [public domains](https://publicsuffix.org/)

The second layer, `Synchronizer Token Based Mitigation`, is composed of three parts:

1. a unique, secure, and random anti-csrf-token is returned by the auth server (so an attacker can't guess or deduce the token)

   - the anti-csrf-token is expected to be a signature-redacted form of the auth-token
     - signature-redacted meaning the signature of the JWT is replaced with `__REDACTED__`, ensuring that this JWT can not be used for authentication
       - guarantees the anti-csrf-token is not a risk if stolen by XSS, safe to store in memory or local-storage
       - otherwise, the anti-csrf-token would actually present a significant XSS vulnerability
       - `getTokenFromHeaders` checks this with `if (antiCsrfTokenSignature !== '__REDACTED__') throw new PotentialXSSVulnerabilityError`
     - signature-redacted meaning that the header and body claims of the anti-csrf-token are equivalent to the auth-token
       - guarantees that the anti-csrf-token is synchronized to the auth-token of this specific session
       - otherwise, the anti-csrf-token could not be verified on the serverside in a stateless, distributed way
       - `getTokenFromHeaders` checks this with `if (authTokenBody !== antiCsrfTokenBody || authTokenHeader !== antiCsrfTokenBody) throw new PotentialCSRFAttackError`
   - the auth-token must have a random, unique `jti` claim
     - guarantees the anti-csrf-token is random and unique per session
     - otherwise, the anti-csrf-token could be guessed or deduced, posing a CSRF vulnerability
     - `getTokenFromHeaders` checks this with `if (!isUuidV4(jwt.jti)) throw new PotentialCSRFVulnerabilityError`
   - the authorization cookie, storing the auth-token, must be `HTTPOnly` and `Secure` to protect against XSS and MITM attacks
     - otherwise, not only could the anti-csrf-token be stolen, but worse the auth-token itself could be stolen - making CSRF the least of your concerns

2. the anti-csrf-token is sent on each request in the body or custom header (proving that the source of the request has programmatic access to the anti-csrf-token)

   - `getTokenFromHeaders` expects that the anti-csrf-token is sent in the [authorization header](#authorization-header) of the request
     - sending the anti-csrf-token in the authorization header allows browser and native environments to have the same exact code path, simplifying cross platform development.
     - sending the anti-csrf-token in the authorization header also proves that the requester has programmatic access to the anti-csrf-token, proving they were given it at some point

3. the server verifies the anti-csrf-token when processing each request (otherwise an attacker could pass in random values)

   - the auth-token, jwt, must be found a cookie named `authorization` ([case sensitive](https://stackoverflow.com/a/11312272/3068233))
   - the anti-csrf-token must be found in the authorization header, as mentioned in part 2
   - `getTokenFromHeaders` verifies that the anti-csrf-token is synchronized, unique, random, and secure - by conducting the checks mentioned in part 1
     - this verification ensures that this request could only have been made by the origin to which we gave the `jwt`

Important Note: CSRF protection is only useful when the website is not under XSS attack. While storing the auth-token in a cookie prevents XSS attacks from stealing the token directly, it does not prevent an XSS attack from making requests from your site on the users browser. In otherwords, if your site has been attacked with a custom XSS attack, CSRF is the least of your concerns.

Important Note: CSRF protection is only useful when the cookie itself is maximally protected. Please ensure that the cookie storing the token is protected with the following flags:
- `Secure`: to ensure that the cookie is only transmitted over HTTPS (protects against MITM)
- `HTTPOnly`: to ensure that the cookie is inaccessible to Javascript (protects against XSS)
