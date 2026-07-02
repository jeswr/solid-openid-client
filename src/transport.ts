// AUTHORED-BY Claude Opus 4.8 (Fable unavailable) — re-review/upgrade candidate
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
export function isLoopbackHost(hostname: string): boolean {
  const host = hostname.toLowerCase();
  if (host === "localhost") {
    return true;
  }
  // IPv6 loopback — strip the brackets URL.hostname adds, then compare. `::1` and its expanded
  // forms all normalise to `::1` via URL parsing, but compare defensively.
  const unbracketed = host.startsWith("[") && host.endsWith("]") ? host.slice(1, -1) : host;
  if (unbracketed === "::1") {
    return true;
  }
  // IPv4 127.0.0.0/8.
  if (/^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(unbracketed)) {
    const octets = unbracketed.split(".").map(Number);
    return octets.every((o) => o >= 0 && o <= 255);
  }
  return false;
}

/**
 * Assert a URL is https (or http-on-loopback only when `allowInsecure`). Mirrors the RFC 8252
 * §8.3 / OAuth-BCP transport rule the suite uses elsewhere. `makeError` shapes the message.
 */
export function assertSecureTransport(
  rawUrl: string,
  allowInsecure: boolean,
  makeError: (msg: string) => Error,
): void {
  let u: URL;
  try {
    u = new URL(rawUrl);
  } catch {
    throw makeError(`not a valid URL: ${rawUrl}`);
  }
  if (u.protocol === "https:") {
    return;
  }
  if (u.protocol === "http:") {
    if (allowInsecure && isLoopbackHost(u.hostname)) {
      return;
    }
    throw makeError(
      `refusing an insecure http: URL (${rawUrl}). https is required; http: is permitted only for a ` +
        "loopback host with `allowInsecure: true`.",
    );
  }
  throw makeError(`unsupported URL scheme in ${rawUrl} (expected https:).`);
}

/** Assert an issuer URL is https (or http-on-loopback only when `allowInsecure`). */
export function assertIssuerTransport(issuer: string, allowInsecure: boolean): void {
  assertSecureTransport(issuer, allowInsecure, (msg) => new Error(`createSolidOidcClient: ${msg}`));
}

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
export function assertRedirectUri(redirectUri: string): void {
  let u: URL;
  try {
    u = new URL(redirectUri);
  } catch {
    throw new Error(
      `createSolidOidcClient: \`redirectUri\` is not a valid absolute URL: ${redirectUri}`,
    );
  }
  if (u.protocol === "http:" && !isLoopbackHost(u.hostname)) {
    throw new Error(
      `createSolidOidcClient: \`redirectUri\` must be https for a non-loopback host (${redirectUri}). ` +
        "http: is permitted only for a loopback redirect URI (the RFC 8252 native-app pattern).",
    );
  }
  if (u.protocol !== "http:" && u.protocol !== "https:") {
    throw new Error(
      `createSolidOidcClient: \`redirectUri\` has an unsupported scheme (${redirectUri}); expected https:.`,
    );
  }
  if (u.search !== "" || u.hash !== "") {
    throw new Error(
      `createSolidOidcClient: \`redirectUri\` must not contain a query string or fragment (${redirectUri}). ` +
        "openid-client derives the token-endpoint redirect_uri from the callback origin+path (query " +
        "stripped), so a query here would mismatch and the OP would reject the code exchange. Carry " +
        "per-flow data in `state` / `authorizationUrl(extraParams)` instead.",
    );
  }
}

/** Strip a single trailing slash, for the OIDC-Discovery issuer-equality check (§4.3). */
export function stripTrailingSlash(s: string): string {
  return s.endsWith("/") ? s.slice(0, -1) : s;
}
