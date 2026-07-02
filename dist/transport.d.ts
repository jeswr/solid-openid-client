/**
 * Transport security policy — the package's plaintext / loopback posture, isolated as pure,
 * synchronous, dependency-free functions so a reviewer can read it as a SPEC:
 *
 *   - `https:` is required for any real host (issuer, discovered endpoints, resource URLs) so a
 *     DPoP access token + proof (a bearer-class secret) is never sent over the wire in the clear.
 *   - `http:` is permitted ONLY for a loopback host, and only where the specific rule allows it
 *     (the RFC 8252 §7.3 native-app / CLI pattern for the redirect URI; behind `allowInsecure`
 *     for a dev OP on the issuer/endpoint/resource legs).
 *
 * None of these functions perform I/O; they operate on plain strings. They are exercised
 * exhaustively by the construction-guard and authed-fetch test suites.
 */
/**
 * True iff `hostname` (as returned by `URL.hostname`) is a loopback host. Handles `localhost`, the
 * whole `127.0.0.0/8` IPv4 loopback range, and IPv6 `::1` — including Node's BRACKETED IPv6 form
 * (`URL.hostname` returns `[::1]` with brackets, so a bare `=== "::1"` check would miss it).
 */
export declare function isLoopbackHost(hostname: string): boolean;
/**
 * Assert a URL is https (or http-on-loopback only when `allowInsecure`). Mirrors the RFC 8252
 * §8.3 / OAuth-BCP transport rule the suite uses elsewhere. `makeError` shapes the message.
 */
export declare function assertSecureTransport(rawUrl: string, allowInsecure: boolean, makeError: (msg: string) => Error): void;
/** Assert an issuer URL is https (or http-on-loopback only when `allowInsecure`). */
export declare function assertIssuerTransport(issuer: string, allowInsecure: boolean): void;
/**
 * Assert the redirect URI is a valid absolute URL, on a safe transport, with NO query/fragment.
 *
 * - Transport: `https:` for any real host; `http:` is permitted for a LOOPBACK host
 *   UNCONDITIONALLY (independent of `allowInsecure`). A loopback redirect URI
 *   (`http://127.0.0.1:<port>/callback`, `[::1]`, `localhost`) is the RFC 8252 §7.3 native-app /
 *   CLI pattern — it never leaves the machine, so it carries no plaintext-over-network risk and
 *   must work against an https issuer without relaxing the issuer/endpoint/resource transport rules
 *   (a roborev finding). A non-loopback `http:` redirect URI is always rejected (an authorization
 *   code would be delivered over plaintext to a real host).
 * - No query/fragment: openid-client v6 derives the token-endpoint `redirect_uri` from the callback
 *   URL's origin+path (query stripped), so a registered redirect URI carrying its own query — e.g.
 *   `https://app.example/callback?tenant=a` — would be sent to the OP as `.../callback`, a mismatch
 *   the OP rejects. We reject it up front with a clear error; carry per-flow data in
 *   `state`/`extraParams`, not the redirect URI's query.
 */
export declare function assertRedirectUri(redirectUri: string): void;
/** Strip a single trailing slash, for the OIDC-Discovery issuer-equality check (§4.3). */
export declare function stripTrailingSlash(s: string): string;
//# sourceMappingURL=transport.d.ts.map