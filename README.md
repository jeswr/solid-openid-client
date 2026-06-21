# @jeswr/solid-openid-client

> ⚠️ **Experimental — AI-agent-generated.** Created by an AI coding agent (Claude Opus 4.8, @jeswr's
> PSS agent) and under active development. It is not yet production-hardened — review before relying
> on it, especially the security-critical auth paths.

A **Solid-OIDC engine wrapping panva's [`openid-client`](https://github.com/panva/openid-client) v6**
— the dominant, well-maintained, audited OAuth 2 / OpenID Connect client for JavaScript. It adds
only the Solid-specific seams on top: the `webid` scope/claim, **DPoP by default** (RFC 9449),
the **Client Identifier Document** public-client path, and a **DPoP-attaching authed `fetch`**.

For **server-side Node apps** — CLIs, backend services, bots, agents — that want to authenticate to
a Solid pod using a trusted OIDC client instead of a bespoke implementation.

DPoP is **not reimplemented**: this package composes [`@jeswr/solid-dpop`](https://github.com/jeswr/solid-dpop)
(the suite's `jose`-only RFC 9449 proof primitives) for key generation and the resource-leg
`ath`-bound proof, and `openid-client`'s own DPoP handle for the token-endpoint proofs.

## Install

```sh
npm install github:jeswr/solid-openid-client#main openid-client
```

`openid-client` is a **peer dependency** — you install + de-dupe your own copy (the whole point is
to wrap *your* audited copy, not ship ours). `@jeswr/solid-dpop` is a normal dependency and is
**bundled into the committed `dist/`**, so the package installs directly from a GitHub branch under
`ignore-scripts=true` with no build step. npm publish is deferred.

> Because `dist/` is committed, **rebuild it (`npm run build`) and commit the result in the same
> change whenever you edit `src/`** — a `check:dist` gate fails the build if the committed `dist/`
> drifts from a fresh build of `src/`.

## Usage

### 1. Web app (server-side redirect flow)

```ts
import { createSolidOidcClient } from "@jeswr/solid-openid-client";

const client = await createSolidOidcClient({
  issuer: "https://solidcommunity.net/",
  clientId: "https://app.example/client-id.jsonld", // a Client Identifier Document (primary path)
  redirectUri: "https://app.example/callback",
});

// --- request handler for GET /login ---
const { url, state } = await client.authorizationUrl();
// Persist `state` server-side (signed cookie / session) keyed to this user-agent, then redirect:
//   res.redirect(url)

// --- request handler for GET /callback ---
const session = await client.handleCallback(
  { url: requestUrl }, // the full callback URL (code + state + iss)
  state,               // the `state` you persisted (PKCE verifier + state + nonce)
);
console.log(session.webId); // the authenticated WebID

// --- authed requests to the pod (DPoP proof attached automatically, ath-bound) ---
const res = await client.fetch(`${session.webId}`); // e.g. fetch the profile
```

### 2. CLI / native app (loopback redirect)

Run a loopback HTTP listener on `127.0.0.1:<port>`, set `redirectUri` to it, open
`authorizationUrl().url` in the browser, and pass the redirected URL to `handleCallback`. Persist
`currentTokens().refreshToken` **and** `dpopKeyPair` (see *Token storage* below) so later runs
refresh without a second browser round-trip.

### 3. Refresh

```ts
const tokens = await client.refresh(); // uses the stored refresh token; rotates it if the OP does
// client.fetch now binds proofs to the new access token automatically
```

## Public API

```ts
function createSolidOidcClient(opts: CreateSolidOidcClientOptions): Promise<SolidOidcClient>;

interface SolidOidcClient {
  readonly issuer: string;
  authorizationUrl(extraParams?: Record<string, string>): Promise<AuthorizationRequest>;
  handleCallback(callback: CallbackInput, state: AuthorizationRequestState): Promise<SolidOidcSession>;
  refresh(refreshToken?: string): Promise<SolidOidcTokens>;
  readonly fetch: FetchLike;            // DPoP-attaching authed fetch (ath-bound to the access token)
  currentTokens(): SolidOidcTokens | undefined;
  currentWebId(): string | undefined;
  readonly dpopKeyPair: DpopKeyPair;    // persist this alongside the refresh token (jkt binding)
}
```

`CreateSolidOidcClientOptions`:

| Option | Required | Notes |
|---|---|---|
| `issuer` | yes | Solid OP URL. Discovery hits `<issuer>/.well-known/openid-configuration`. |
| `redirectUri` | yes | The registered OAuth redirect URI. |
| `clientId` | one-of | A Client Identifier Document `https:` URL — the **primary** path. |
| `client` | one-of | A full client identity (Client ID Document or a static/confidential client). |
| `scope` | no | Default `"openid webid offline_access"`. `openid` is forced on. |
| `dpopKeyPair` | no | Reuse a persisted keypair so the refresh-token `jkt` binding survives a restart. |
| `fetch` | no | Inject a custom `fetch` (the test seam / an SSRF-guarded fetch in prod). |
| `allowInsecure` | no | Allow an `http:` issuer **only** for a loopback dev OP. Off by default. |

The returned helpers (`authorizationUrl`, `handleCallback`, `refresh`, `fetch`) and the supporting
types (`SolidOidcSession`, `SolidOidcTokens`, `AuthorizationRequest`, `AuthorizationRequestState`,
`CallbackInput`, `ClientIdentity`, …) are all exported from the package root. The DPoP bridge
(`generateDpopKeyPair`, `resourceDpopProof`, `toCryptoKeyPair`, `DpopKeyPair`) is re-exported too.

## Design decisions

These are this package's choices (the maintainer can steer them — see the open design issue):

1. **Wrap `openid-client` v6, don't fork it.** `openid-client` is the dominant, audited OIDC client.
   We add Solid seams (the `webid` scope/claim, DPoP-by-default, the Client ID Document path, a
   reusable authed `fetch`) and otherwise lean on the engine for discovery, PKCE, code exchange,
   ID-token validation (signature / `iss` / `aud` / `nonce`), and refresh.

2. **Compose `@jeswr/solid-dpop`, don't reimplement DPoP.** DPoP appears twice and we route both
   through the suite's vetted primitive: (a) **key generation** — `@jeswr/solid-dpop` owns the
   algorithm policy (ES256, asymmetric-only, extractable, RFC 7638 thumbprint); (b) the
   **resource-leg proof** — built with `@jeswr/solid-dpop`'s `createDpopProof` so the `ath`
   binding a Solid pod relies on is the suite's audited code. The **token-endpoint proofs** use
   `openid-client`'s own DPoP handle (bound to the *same* keypair), because it additionally tracks
   the server's `DPoP-Nonce` (RFC 9449 §8) across the token requests for us.

3. **Client Identifier Document is the primary client path; DCR is a documented seam.** A Client ID
   Document public client shows a stable named client on the consent screen and has no secret to
   manage — the recommended Solid-OIDC public-client pattern. Dynamic client registration is
   supported by supplying a full `client` identity you registered yourself; it is not the default.

4. **Token storage is an injectable seam — the consumer persists.** The client never writes to disk.
   It exposes `currentTokens()` (incl. the refresh token) and `dpopKeyPair`; persist both yourself.
   The DPoP private key **must** be persisted with the refresh token because the OP binds the
   refresh token to the keypair's `jkt` — a refresh signed by a regenerated key is rejected.

5. **Fail-closed on the WebID.** A login produces no session unless a resolvable `http(s)` `webid`
   claim is present (read from the verified ID token, falling back to the access token). No WebID →
   `handleCallback` throws.

6. **Asymmetric DPoP, PKCE always, state + nonce always, no token logging, TLS issuers.** PKCE
   (S256), a random `state` (CSRF), and a random `nonce` (ID-token binding) are generated and
   validated on **every** flow regardless of OP metadata. `http:` issuers are rejected unless
   `allowInsecure` is set for a loopback dev OP. Tokens are never logged.

## Security

This is an **auth package**. The flow is tested exhaustively against a **faithful mock OP** (no live
IdP, no network, no ports): the mock signs **real ES256 ID tokens**, serves a real JWKS, and
verifies PKCE S256 — so `openid-client` genuinely validates / rejects and the tests are non-vacuous.
Covered: happy path (code → DPoP-bound tokens → WebID), WebID from the access token, **PKCE
mismatch fails**, **state mismatch fails**, **nonce mismatch fails**, **missing-WebID fails
(fail-closed)**, opaque-access-token-with-no-WebID fails, non-`http(s)` WebID fails, **refresh
round-trips a new DPoP-bound token + rotated refresh token**, the **authed `fetch` attaches a valid
DPoP proof with `ath` = SHA-256(access_token) and `jkt` matching the keypair**, the §8 `DPoP-Nonce`
retry, a fresh `jti` per request, and the transport guards.

## License

MIT © Jesse Wright
