/**
 * DOM-`fetch` / openid-client interop adapters — the small, boundary-crossing glue that lets the
 * engine present a plain DOM-shaped `fetch` outward while feeding openid-client the shapes it
 * expects. Isolated so the flow orchestration in `client.ts` reads as the protocol, not the plumbing:
 *
 *   - `resolveUrl` — browser-faithful relative-URL resolution (honours `<base href>`), strict on Node.
 *   - `callbackToUrl` — build the authorization-response URL on the REGISTERED redirect URI,
 *     preserving duplicate params so oauth4webapi can fail closed on parameter pollution.
 *   - `requestTransportFields` — carry a `Request`'s transport semantics through the fetch replacement.
 *   - `adaptCustomFetch` — bridge a DOM `fetch` to openid-client's narrower `CustomFetch` shape,
 *     preserving its `redirect: "manual"` contract.
 */
import type * as oidc from "openid-client";
import type { CallbackInput, FetchLike } from "./types.js";
/**
 * Resolve a string/URL `fetch` input to an absolute URL string, the way browser `fetch` does: a
 * relative URL is resolved against the document base when present (a browser/worker), else it must
 * be absolute (server-side Node has no base — a relative URL throws a clear error). This keeps the
 * authed `fetch` a drop-in for the DOM `fetch` in a browser context while staying strict
 * server-side.
 *
 * The base is `document.baseURI` (which honours a `<base href>`) when in a document context —
 * matching native `fetch` exactly — falling back to `location.href` for a worker-like context.
 */
export declare function resolveUrl(input: string | URL): string;
/**
 * Turn a {@link CallbackInput} into the `URL` openid-client expects, with the params-form URL built
 * on the REGISTERED `redirectUri`.
 *
 * openid-client v6 derives the `redirect_uri` it sends to the token endpoint from this URL's
 * origin+path. The params form must therefore be assembled on the real `redirectUri` base (NOT a
 * placeholder), otherwise the OP receives a mismatched/invalid `redirect_uri` and rejects the code
 * exchange (a roborev finding). For the `url` form the caller already supplies the full callback
 * URL (which is the redirect URI + the response params), so we use it as-is.
 */
export declare function callbackToUrl(callback: CallbackInput, redirectUri: string): URL;
/**
 * Extract the transport-relevant fields of a `Request` into a `RequestInit`, so replacing the
 * Request with `userFetch(url, init)` does not silently drop fetch semantics (credentials, mode,
 * cache, redirect, integrity, keepalive, referrer, referrerPolicy, signal). `body`/`method`/
 * `headers` are handled separately by the authed-fetch buffering + header-merge logic.
 */
export declare function requestTransportFields(req: Request): RequestInit;
/**
 * Adapt a DOM-shaped {@link FetchLike} into openid-client's `CustomFetch`
 * (`(url, CustomFetchOptions) => Promise<Response>`). `CustomFetchOptions` is structurally a
 * subset of `RequestInit` (`body`/`headers`/`method`/`redirect`/`signal`), so it forwards
 * directly. We preserve openid-client's `redirect: "manual"` (it relies on inspecting redirects
 * itself, not following them) and pass through the abort `signal`.
 */
export declare function adaptCustomFetch(userFetch: FetchLike): oidc.CustomFetch;
//# sourceMappingURL=request-adapter.d.ts.map