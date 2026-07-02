// AUTHORED-BY Claude Opus 4.8 (Fable unavailable) — re-review/upgrade candidate
/**
 * The DPoP-attaching authed `fetch` — the resource-leg adapter of the Solid-OIDC flow, factored
 * out of the client so this security-critical runtime path reads as ONE named unit with EXPLICIT
 * dependencies (rather than a 100-line closure buried in the factory). It is the resource-side
 * counterpart to openid-client's token-leg: it builds each request's RFC 9449 §4.2 proof (with the
 * `ath` access-token binding) via `@jeswr/solid-dpop`, and retries once on a §8 `DPoP-Nonce`
 * challenge.
 *
 * Its invariants (essential security complexity — preserved verbatim, not flattened):
 *   - the DPoP token is NEVER sent over a plaintext URL (transport asserted BEFORE any header/proof);
 *   - `Request` + `init` are merged faithfully (an explicit `init` field overrides the `Request`'s);
 *   - the body is BUFFERED once up front so the §8 retry can REPLAY it (a stream would otherwise be
 *     consumed by the first attempt);
 *   - the access token is read LIVE per call (via `getAccessToken`) so a proof always binds to the
 *     current token, including after a refresh.
 */

import type { DpopKeyPair } from "@jeswr/solid-dpop";
import { bufferBody, readStreamWithSignal } from "./body-buffer.js";
import { resourceDpopProof } from "./dpop.js";
import { requestTransportFields, resolveUrl } from "./request-adapter.js";
import { assertSecureTransport } from "./transport.js";
import type { FetchLike } from "./types.js";

/** Everything the authed `fetch` needs, injected explicitly so it has no hidden state. */
export interface AuthedFetchDeps {
  /**
   * Read the CURRENT access token (or `undefined` before any login). Read live per request so a
   * proof binds to the latest token after a refresh; `undefined` means "no token yet" → throw.
   */
  readonly getAccessToken: () => string | undefined;
  /** The DPoP keypair the tokens are bound to (its thumbprint == the token `jkt`). */
  readonly dpopKeyPair: DpopKeyPair;
  /** Whether http-on-loopback is permitted (dev). https is otherwise required (no plaintext token). */
  readonly allowInsecure: boolean;
  /** Cap (bytes) on a buffered stream body for §8 replay. */
  readonly maxReplayBodyBytes: number;
  /** The underlying DOM-shaped fetch (test seam / SSRF-guarded fetch in prod). */
  readonly userFetch: FetchLike;
}

/**
 * Build the DPoP-attaching authed `fetch`. Binds every request to the current access token (`ath`)
 * and retries once on a server `DPoP-Nonce` challenge (RFC 9449 §8). Throws if called before any
 * token is available.
 *
 * It handles a `Request` input AND an `init` faithfully: the effective method/headers/body are
 * resolved from BOTH (an explicit `init` field overrides the `Request`'s), so a `POST`/`PUT`
 * `Request` passed with no `init` keeps its method + body (a bug fixed per a roborev finding).
 * The body is BUFFERED once up front (to a string/ArrayBuffer) so the §8 nonce retry can replay
 * it — a non-replayable stream body would otherwise be consumed by the first attempt.
 */
export function createAuthedFetch(deps: AuthedFetchDeps): FetchLike {
  const { getAccessToken, dpopKeyPair, allowInsecure, maxReplayBodyBytes, userFetch } = deps;

  return async (input, init) => {
    const accessToken = getAccessToken();
    if (accessToken === undefined) {
      throw new Error(
        "authedFetch: no access token yet — call handleCallback()/refresh() before fetching.",
      );
    }
    const reqInput = input instanceof Request ? input : undefined;
    // A `Request` always carries an absolute `.url`. A string/URL input may be RELATIVE (browser
    // `fetch` resolves it against the document base); resolve it the same way so we don't reject a
    // valid relative URL — and so the transport check + `htu` + the fetch all use one absolute URL.
    const url = input instanceof Request ? input.url : resolveUrl(input);

    // SECURITY: never attach the DPoP access token + proof to a plaintext URL — that would leak the
    // bearer-class token over the wire. Require https (http only on loopback when allowInsecure),
    // BEFORE building any header/proof (a roborev finding).
    assertSecureTransport(
      url,
      allowInsecure,
      (msg) => new Error(`authedFetch: ${msg} — refusing to send the DPoP token over plaintext.`),
    );

    // Effective method: explicit init wins, else the Request's, else GET.
    const method = (init?.method ?? reqInput?.method ?? "GET").toUpperCase();

    // Effective base RequestInit, carrying over ALL relevant transport fields from the Request
    // first, then letting an explicit init override them, so nothing (mode/credentials/cache/
    // redirect/integrity/keepalive/referrer/referrerPolicy/signal/…) is silently dropped when we
    // replace the original `Request` with `userFetch(url, init)`.
    const baseInit: RequestInit = {
      ...(reqInput ? requestTransportFields(reqInput) : {}),
      ...(init ?? {}),
      method,
    };
    // `body` is owned by the buffering logic below — never leak the original (possibly already
    // consumed) stream from baseInit into the per-attempt RequestInit.
    delete (baseInit as { body?: unknown }).body;

    // The effective abort signal (explicit init wins, else the Request's). It is honoured both
    // while BUFFERING a stream body (so an abort during the read rejects promptly instead of
    // draining the stream) and is carried into the per-attempt RequestInit via baseInit.
    const effectiveSignal: AbortSignal | undefined =
      init && "signal" in init ? (init.signal ?? undefined) : (reqInput?.signal ?? undefined);

    // Buffer the body ONCE so it is REPLAYABLE across the original + nonce-retry attempts — a
    // non-replayable stream (a `Request` body, or a `ReadableStream` passed via init.body) would
    // otherwise be consumed by the first attempt and the §8 retry would send an empty/locked body.
    // Precedence matches `fetch`: an explicit `init.body` wins over the Request's body.
    let bufferedBody: BodyInit | undefined;
    if (init && "body" in init) {
      bufferedBody = await bufferBody(
        (init.body ?? undefined) as BodyInit | null | undefined,
        effectiveSignal,
        maxReplayBodyBytes,
      );
    } else if (reqInput && reqInput.body !== null) {
      // A Request body is a stream; read it (abort-aware, cancellable, size-capped) so we can send
      // it more than once across the original + nonce retry.
      bufferedBody = await readStreamWithSignal(
        reqInput.clone().body as ReadableStream<Uint8Array>,
        effectiveSignal,
        maxReplayBodyBytes,
      );
    }

    // Merge headers from the Request then the init (init overrides), so a Request's content-type
    // etc. is preserved while an explicit init header still wins.
    const buildHeaders = (proof: string): Headers => {
      const headers = new Headers(reqInput?.headers ?? undefined);
      if (init?.headers) {
        new Headers(init.headers).forEach((v, k) => {
          headers.set(k, v);
        });
      }
      headers.set("authorization", `DPoP ${accessToken}`);
      headers.set("dpop", proof);
      return headers;
    };

    const doFetch = async (nonce?: string): Promise<Response> => {
      const proof = await resourceDpopProof(dpopKeyPair, method, url, accessToken, nonce);
      const req: RequestInit = {
        ...baseInit,
        headers: buildHeaders(proof),
        ...(bufferedBody !== undefined ? { body: bufferedBody } : {}),
      };
      return userFetch(url, req);
    };

    const res = await doFetch();
    // §8 nonce challenge: a 401 with a `DPoP-Nonce` header → retry once echoing the nonce.
    if (res.status === 401) {
      const serverNonce = res.headers.get("dpop-nonce");
      if (serverNonce) {
        // Drain the challenge response body before retrying so its connection/body resources are
        // released (we discard it — only the retry's response is returned). Best-effort.
        await res.body?.cancel().catch(() => {});
        return doFetch(serverNonce);
      }
    }
    return res;
  };
}
