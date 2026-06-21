// src/client.ts
import * as oidc from "openid-client";

// node_modules/@jeswr/solid-dpop/dist/esm/authCode.js
import { createHash as createHash2, randomBytes, randomUUID as randomUUID2 } from "node:crypto";

// node_modules/@jeswr/solid-dpop/dist/esm/dpop.js
import { createHash, randomUUID } from "node:crypto";
var josePromise;
function loadJose() {
  if (!josePromise) {
    josePromise = import("jose");
  }
  return josePromise;
}
var DPOP_ALG = "ES256";
function canonicalHtu(uri) {
  const u = new URL(uri);
  u.search = "";
  u.hash = "";
  return u.toString();
}
function accessTokenHash(accessToken) {
  return createHash("sha256").update(accessToken, "ascii").digest("base64url");
}
async function toDpopKeyPair(publicKey, privateKey) {
  const { exportJWK, calculateJwkThumbprint } = await loadJose();
  const publicJwk = await exportJWK(publicKey);
  const thumbprint = await calculateJwkThumbprint(publicJwk);
  return { publicKey, privateKey, publicJwk, thumbprint };
}
async function generateDpopKeyPair() {
  const { generateKeyPair } = await loadJose();
  const { publicKey, privateKey } = await generateKeyPair(DPOP_ALG, { extractable: true });
  return toDpopKeyPair(publicKey, privateKey);
}
async function createDpopProof(params) {
  const { keyPair, htm, htu, accessToken, nonce } = params;
  const payload = {
    htm: htm.toUpperCase(),
    htu: canonicalHtu(htu),
    jti: randomUUID()
  };
  if (accessToken !== void 0) {
    payload["ath"] = accessTokenHash(accessToken);
  }
  if (nonce !== void 0) {
    payload["nonce"] = nonce;
  }
  const { SignJWT } = await loadJose();
  return new SignJWT(payload).setProtectedHeader({
    typ: "dpop+jwt",
    alg: DPOP_ALG,
    jwk: keyPair.publicJwk
  }).setIssuedAt().sign(keyPair.privateKey);
}

// src/dpop.ts
function toCryptoKeyPair(keyPair) {
  return { publicKey: keyPair.publicKey, privateKey: keyPair.privateKey };
}
function resourceDpopProof(keyPair, method, url, accessToken, nonce) {
  return createDpopProof(
    nonce === void 0 ? { keyPair, htm: method, htu: url, accessToken } : { keyPair, htm: method, htu: url, accessToken, nonce }
  );
}

// src/client.ts
var DEFAULT_SCOPE2 = "openid webid offline_access";
var DEFAULT_MAX_REPLAY_BODY_BYTES = 10 * 1024 * 1024;
var RESERVED_AUTH_PARAMS = /* @__PURE__ */ new Set([
  "client_id",
  "redirect_uri",
  "scope",
  "response_type",
  "code_challenge",
  "code_challenge_method",
  "state",
  "nonce"
]);
function normalizeScope(scope) {
  if (scope === void 0 || scope.trim() === "") {
    return DEFAULT_SCOPE2;
  }
  const parts = scope.split(/\s+/).filter((s) => s.length > 0);
  if (!parts.includes("openid")) {
    parts.unshift("openid");
  }
  return [...new Set(parts)].join(" ");
}
function resolveIdentity(opts) {
  if (opts.client !== void 0 && opts.clientId !== void 0) {
    throw new Error(
      "createSolidOidcClient: supply EITHER `clientId` (a Client ID Document URL) OR `client`, not both."
    );
  }
  if (opts.client !== void 0) {
    return opts.client;
  }
  if (opts.clientId !== void 0) {
    return { clientId: opts.clientId };
  }
  throw new Error(
    "createSolidOidcClient: a client identity is required \u2014 pass `clientId` (a Client ID Document URL, the primary path) or a full `client`."
  );
}
function hasSecret(id) {
  return "clientSecret" in id && typeof id.clientSecret === "string" && id.clientSecret.length > 0;
}
function isLoopbackHost2(hostname) {
  const host = hostname.toLowerCase();
  if (host === "localhost") {
    return true;
  }
  const unbracketed = host.startsWith("[") && host.endsWith("]") ? host.slice(1, -1) : host;
  if (unbracketed === "::1") {
    return true;
  }
  if (/^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(unbracketed)) {
    const octets = unbracketed.split(".").map(Number);
    return octets.every((o) => o >= 0 && o <= 255);
  }
  return false;
}
function assertSecureTransport(rawUrl, allowInsecure, makeError) {
  let u;
  try {
    u = new URL(rawUrl);
  } catch {
    throw makeError(`not a valid URL: ${rawUrl}`);
  }
  if (u.protocol === "https:") {
    return;
  }
  if (u.protocol === "http:") {
    if (allowInsecure && isLoopbackHost2(u.hostname)) {
      return;
    }
    throw makeError(
      `refusing an insecure http: URL (${rawUrl}). https is required; http: is permitted only for a loopback host with \`allowInsecure: true\`.`
    );
  }
  throw makeError(`unsupported URL scheme in ${rawUrl} (expected https:).`);
}
function assertIssuerTransport2(issuer, allowInsecure) {
  assertSecureTransport(issuer, allowInsecure, (msg) => new Error(`createSolidOidcClient: ${msg}`));
}
function extractWebId(tokenResponse) {
  const idClaims = tokenResponse.claims();
  const fromWebidClaim = idClaims?.webid;
  if (typeof fromWebidClaim === "string" && isHttpUri(fromWebidClaim)) {
    return fromWebidClaim;
  }
  const fromSub = idClaims?.sub;
  if (typeof fromSub === "string" && isHttpUri(fromSub)) {
    return fromSub;
  }
  throw new Error(
    "Solid-OIDC login produced no resolvable `webid` claim in the VERIFIED ID token; refusing to return a session without a verified WebID (fail-closed). The WebID is never trusted from an unverified access token."
  );
}
function isHttpUri(value) {
  try {
    const u = new URL(value);
    return u.protocol === "https:" || u.protocol === "http:";
  } catch {
    return false;
  }
}
function toSolidTokens(res) {
  const base = {
    accessToken: res.access_token,
    tokenType: res.token_type
  };
  return {
    ...base,
    ...res.refresh_token !== void 0 ? { refreshToken: res.refresh_token } : {},
    ...res.id_token !== void 0 ? { idToken: res.id_token } : {},
    ...res.expires_in !== void 0 ? { expiresIn: res.expires_in } : {},
    ...res.scope !== void 0 ? { scope: res.scope } : {}
  };
}
async function createSolidOidcClient(opts) {
  const allowInsecure = opts.allowInsecure === true;
  assertIssuerTransport2(opts.issuer, allowInsecure);
  const identity = resolveIdentity(opts);
  const scope = normalizeScope(opts.scope);
  const redirectUri = opts.redirectUri;
  const maxReplayBodyBytes = opts.maxReplayBodyBytes ?? DEFAULT_MAX_REPLAY_BODY_BYTES;
  const userFetch = opts.fetch ?? globalThis.fetch;
  const dpopKeyPair = opts.dpopKeyPair ?? await generateDpopKeyPair();
  const baseMetadata = {
    client_id: identity.clientId,
    redirect_uris: [redirectUri],
    ..."clientMetadata" in identity && identity.clientMetadata || {}
  };
  const clientAuth = hasSecret(identity) ? oidc.ClientSecretPost(identity.clientSecret) : oidc.None();
  if (hasSecret(identity)) {
    baseMetadata.client_secret = identity.clientSecret;
  }
  const discoveryOptions = {
    [oidc.customFetch]: adaptCustomFetch(userFetch),
    ...allowInsecure ? { execute: [oidc.allowInsecureRequests] } : {}
  };
  const config = await oidc.discovery(
    new URL(opts.issuer),
    identity.clientId,
    baseMetadata,
    clientAuth,
    discoveryOptions
  );
  const discoveredIssuer = config.serverMetadata().issuer;
  if (discoveredIssuer !== opts.issuer && discoveredIssuer !== stripTrailingSlash(opts.issuer)) {
    if (stripTrailingSlash(discoveredIssuer) !== stripTrailingSlash(opts.issuer)) {
      throw new Error(
        `createSolidOidcClient: discovered issuer (${discoveredIssuer}) does not match the requested issuer (${opts.issuer}).`
      );
    }
  }
  const dpopHandle = oidc.getDPoPHandle(config, toCryptoKeyPair(dpopKeyPair));
  let currentTokens;
  let currentWebId;
  const authedFetch2 = async (input, init) => {
    if (currentTokens === void 0) {
      throw new Error(
        "authedFetch: no access token yet \u2014 call handleCallback()/refresh() before fetching."
      );
    }
    const accessToken = currentTokens.accessToken;
    const reqInput = input instanceof Request ? input : void 0;
    const url = reqInput ? reqInput.url : input.toString();
    assertSecureTransport(
      url,
      allowInsecure,
      (msg) => new Error(`authedFetch: ${msg} \u2014 refusing to send the DPoP token over plaintext.`)
    );
    const method = (init?.method ?? reqInput?.method ?? "GET").toUpperCase();
    const baseInit = {
      ...reqInput ? requestTransportFields(reqInput) : {},
      ...init ?? {},
      method
    };
    delete baseInit.body;
    const effectiveSignal = init && "signal" in init ? init.signal ?? void 0 : reqInput?.signal ?? void 0;
    let bufferedBody;
    if (init && "body" in init) {
      bufferedBody = await bufferBody(
        init.body ?? void 0,
        effectiveSignal,
        maxReplayBodyBytes
      );
    } else if (reqInput && reqInput.body !== null) {
      bufferedBody = await readStreamWithSignal(
        reqInput.clone().body,
        effectiveSignal,
        maxReplayBodyBytes
      );
    }
    const buildHeaders = (proof) => {
      const headers = new Headers(reqInput?.headers ?? void 0);
      if (init?.headers) {
        new Headers(init.headers).forEach((v, k) => {
          headers.set(k, v);
        });
      }
      headers.set("authorization", `DPoP ${accessToken}`);
      headers.set("dpop", proof);
      return headers;
    };
    const doFetch = async (nonce) => {
      const proof = await resourceDpopProof(dpopKeyPair, method, url, accessToken, nonce);
      const req = {
        ...baseInit,
        headers: buildHeaders(proof),
        ...bufferedBody !== void 0 ? { body: bufferedBody } : {}
      };
      return userFetch(url, req);
    };
    const res = await doFetch();
    if (res.status === 401) {
      const serverNonce = res.headers.get("dpop-nonce");
      if (serverNonce) {
        return doFetch(serverNonce);
      }
    }
    return res;
  };
  return {
    issuer: opts.issuer,
    dpopKeyPair,
    fetch: authedFetch2,
    currentTokens: () => currentTokens,
    currentWebId: () => currentWebId,
    async authorizationUrl(extraParams) {
      const codeVerifier = oidc.randomPKCECodeVerifier();
      const codeChallenge = await oidc.calculatePKCECodeChallenge(codeVerifier);
      const state = oidc.randomState();
      const nonce = oidc.randomNonce();
      if (extraParams) {
        const overridden = Object.keys(extraParams).filter((k) => RESERVED_AUTH_PARAMS.has(k));
        if (overridden.length > 0) {
          throw new Error(
            `authorizationUrl: extraParams must not override reserved parameter(s): ${overridden.join(", ")}. These (PKCE, state, nonce, scope, response_type, redirect_uri, client_id) are generated by the engine.`
          );
        }
      }
      const params = {
        ...extraParams ?? {},
        redirect_uri: redirectUri,
        scope,
        response_type: "code",
        code_challenge: codeChallenge,
        code_challenge_method: "S256",
        state,
        nonce
      };
      const url = oidc.buildAuthorizationUrl(config, params);
      return {
        url: url.href,
        state: { codeVerifier, state, nonce, redirectUri }
      };
    },
    async handleCallback(callback, reqState) {
      const currentUrl = callbackToUrl(callback, reqState.redirectUri);
      const tokenResponse = await oidc.authorizationCodeGrant(
        config,
        currentUrl,
        {
          pkceCodeVerifier: reqState.codeVerifier,
          expectedState: reqState.state,
          // exact-match CSRF check (openid-client throws on mismatch)
          expectedNonce: reqState.nonce,
          // exact-match ID-token nonce check
          idTokenExpected: true
          // a Solid-OIDC login MUST return an ID token
        },
        void 0,
        { DPoP: dpopHandle }
      );
      const webId = extractWebId(tokenResponse);
      const tokens = toSolidTokens(tokenResponse);
      currentTokens = tokens;
      currentWebId = webId;
      return { webId, issuer: opts.issuer, tokens };
    },
    async refresh(refreshTokenArg) {
      const refreshToken = refreshTokenArg ?? currentTokens?.refreshToken;
      if (refreshToken === void 0) {
        throw new Error(
          "refresh: no refresh token available \u2014 supply one or log in with `offline_access` first."
        );
      }
      const res = await oidc.refreshTokenGrant(config, refreshToken, void 0, {
        DPoP: dpopHandle
      });
      let tokens = toSolidTokens(res);
      if (tokens.refreshToken === void 0) {
        tokens = { ...tokens, refreshToken };
      }
      currentTokens = tokens;
      const refreshedWebId = res.claims()?.webid;
      if (typeof refreshedWebId === "string" && isHttpUri(refreshedWebId)) {
        currentWebId = refreshedWebId;
      }
      return tokens;
    }
  };
}
function callbackToUrl(callback, redirectUri) {
  if ("url" in callback) {
    return callback.url instanceof URL ? callback.url : new URL(callback.url);
  }
  const u = new URL(redirectUri);
  const params = callback.params instanceof URLSearchParams ? callback.params : new URLSearchParams(callback.params);
  for (const [k, v] of params) {
    u.searchParams.set(k, v);
  }
  return u;
}
function stripTrailingSlash(s) {
  return s.endsWith("/") ? s.slice(0, -1) : s;
}
function requestTransportFields(req) {
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
    ...req.signal ? { signal: req.signal } : {}
  };
}
async function bufferBody(body, signal, maxBytes) {
  if (body === null || body === void 0) {
    return void 0;
  }
  if (body instanceof ReadableStream) {
    return readStreamWithSignal(body, signal, maxBytes);
  }
  return body;
}
async function readStreamWithSignal(stream, signal, maxBytes) {
  const reader = stream.getReader();
  let removeAbortListener;
  const abortRace = signal === void 0 ? void 0 : new Promise((_resolve, reject) => {
    const onAbort = () => reject(abortReason(signal));
    signal.addEventListener("abort", onAbort, { once: true });
    removeAbortListener = () => signal.removeEventListener("abort", onAbort);
  });
  abortRace?.catch(() => {
  });
  const chunks = [];
  let total = 0;
  try {
    if (signal?.aborted) {
      throw abortReason(signal);
    }
    for (; ; ) {
      const result = abortRace ? await Promise.race([reader.read(), abortRace]) : await reader.read();
      if (result.done) {
        break;
      }
      total += result.value.byteLength;
      if (total > maxBytes) {
        throw new Error(
          `authedFetch: request stream body exceeds the ${maxBytes}-byte replay buffer cap. Raise \`maxReplayBodyBytes\` to upload a larger body (it is buffered so the \xA78 DPoP-nonce retry can replay it).`
        );
      }
      chunks.push(result.value);
    }
  } catch (err) {
    await reader.cancel(err).catch(() => {
    });
    throw err;
  } finally {
    removeAbortListener?.();
    reader.releaseLock();
  }
  const out = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return out.buffer.slice(0, total);
}
function abortReason(signal) {
  const reason = signal.reason;
  if (reason !== void 0) {
    return reason;
  }
  return new DOMException("The operation was aborted.", "AbortError");
}
function adaptCustomFetch(userFetch) {
  return (url, options) => {
    const init = {
      method: options.method,
      headers: options.headers,
      redirect: options.redirect,
      ...options.body !== void 0 ? { body: options.body } : {},
      ...options.signal !== void 0 ? { signal: options.signal } : {}
    };
    return userFetch(url, init);
  };
}
export {
  DEFAULT_MAX_REPLAY_BODY_BYTES,
  DEFAULT_SCOPE2 as DEFAULT_SCOPE,
  createSolidOidcClient,
  generateDpopKeyPair,
  resourceDpopProof,
  toCryptoKeyPair
};
//# sourceMappingURL=index.js.map
