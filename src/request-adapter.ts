// AUTHORED-BY Claude Opus 4.8 (Fable unavailable) — re-review/upgrade candidate
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
export function resolveUrl(input: string | URL): string {
  if (input instanceof URL) {
    return input.toString();
  }
  const g = globalThis as {
    document?: { baseURI?: string };
    location?: { href?: string };
  };
  const base = g.document?.baseURI ?? g.location?.href;
  try {
    return base !== undefined ? new URL(input, base).toString() : new URL(input).toString();
  } catch {
    throw new Error(
      `authedFetch: \`${input}\` is not an absolute URL and there is no document base to resolve it ` +
        "against (server-side). Pass an absolute https URL.",
    );
  }
}

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
export function callbackToUrl(callback: CallbackInput, redirectUri: string): URL {
  if ("url" in callback) {
    return callback.url instanceof URL ? callback.url : new URL(callback.url);
  }
  // Params form: build the URL on the registered redirect URI so the derived redirect_uri is
  // correct. The redirect URI is guaranteed query-free (asserted at construction), so we APPEND the
  // response params — preserving DUPLICATES (e.g. a polluted `code`/`state`/`iss`/`error`) so
  // openid-client / oauth4webapi sees the original parameters and fails closed on pollution, rather
  // than us silently collapsing them with `set()` (a roborev finding).
  const u = new URL(redirectUri);
  const params =
    callback.params instanceof URLSearchParams
      ? callback.params
      : new URLSearchParams(callback.params);
  for (const [k, v] of params) {
    u.searchParams.append(k, v);
  }
  return u;
}

/**
 * Extract the transport-relevant fields of a `Request` into a `RequestInit`, so replacing the
 * Request with `userFetch(url, init)` does not silently drop fetch semantics (credentials, mode,
 * cache, redirect, integrity, keepalive, referrer, referrerPolicy, signal). `body`/`method`/
 * `headers` are handled separately by the authed-fetch buffering + header-merge logic.
 */
export function requestTransportFields(req: Request): RequestInit {
  return {
    method: req.method,
    redirect: req.redirect,
    cache: req.cache,
    credentials: req.credentials,
    integrity: req.integrity,
    keepalive: req.keepalive,
    mode: req.mode,
    referrer: req.referrer,
    referrerPolicy: req.referrerPolicy,
    ...(req.signal ? { signal: req.signal } : {}),
  };
}

/**
 * Adapt a DOM-shaped {@link FetchLike} into openid-client's `CustomFetch`
 * (`(url, CustomFetchOptions) => Promise<Response>`). `CustomFetchOptions` is structurally a
 * subset of `RequestInit` (`body`/`headers`/`method`/`redirect`/`signal`), so it forwards
 * directly. We preserve openid-client's `redirect: "manual"` (it relies on inspecting redirects
 * itself, not following them) and pass through the abort `signal`.
 */
export function adaptCustomFetch(userFetch: FetchLike): oidc.CustomFetch {
  return (url, options) => {
    const init: RequestInit = {
      method: options.method,
      headers: options.headers,
      redirect: options.redirect,
      ...(options.body !== undefined ? { body: options.body as BodyInit } : {}),
      ...(options.signal !== undefined ? { signal: options.signal } : {}),
    };
    return userFetch(url, init);
  };
}
