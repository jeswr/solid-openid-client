/**
 * DPoP bridge — composes `@jeswr/solid-dpop` (the suite's vetted RFC 9449 primitives) with
 * panva's `openid-client` v6, so we DO NOT reimplement DPoP.
 *
 * DPoP appears in two places in the Solid-OIDC flow, and we route BOTH through `@jeswr/solid-dpop`:
 *
 *   1. The OAuth token-endpoint proofs (code exchange + refresh). `openid-client` v6 signs these
 *      itself via a "DPoP handle" wrapping a `CryptoKeyPair`. We hand it the SAME asymmetric
 *      keypair `@jeswr/solid-dpop` generated (`generateDpopKeyPair` → ES256, extractable), so the
 *      suite owns key generation policy (algorithm, thumbprint) and the token's `jkt` binding is
 *      the suite keypair's thumbprint. openid-client only does the proof-signing mechanics around
 *      that key — and its handle additionally tracks server nonces (RFC 9449 §8) for the token
 *      endpoint, which is exactly what we want there.
 *
 *   2. The resource-request proofs (the authed `fetch`). We build these directly with
 *      `@jeswr/solid-dpop`'s `createDpopProof` — including the `ath` (access-token hash) claim
 *      that binds the proof to the specific access token (RFC 9449 §4.2 / §6.1) — rather than
 *      letting openid-client own the resource leg. This keeps the resource-side proof generation
 *      (the security-critical `ath` binding a Solid pod relies on) in the suite's audited
 *      primitive, and decouples the authed `fetch` from openid-client's `fetchProtectedResource`
 *      so a consumer can use the returned `fetch` like any DOM `fetch`.
 *
 * Nothing crypto is hand-rolled here: key generation, JWS signing, thumbprints, and the `ath`
 * digest all come from `@jeswr/solid-dpop` (which is `jose`-only).
 */
import { type DpopKeyPair, generateDpopKeyPair } from "@jeswr/solid-dpop";
/** Re-export so callers persist/restore a keypair without a second dependency. */
export { type DpopKeyPair, generateDpopKeyPair };
/**
 * The shape `openid-client` v6's `getDPoPHandle` expects: a `CryptoKeyPair`
 * (`{ publicKey, privateKey }`). A `@jeswr/solid-dpop` `DpopKeyPair` is a superset of this
 * (it additionally carries the exported public JWK + thumbprint), so we project to just the
 * two keys. We assert the type structurally — both are WebCrypto `CryptoKey`s.
 */
export interface CryptoKeyPairLike {
    readonly publicKey: CryptoKey;
    readonly privateKey: CryptoKey;
}
/** Project a suite `DpopKeyPair` down to the `CryptoKeyPair` openid-client's DPoP handle wants. */
export declare function toCryptoKeyPair(keyPair: DpopKeyPair): CryptoKeyPairLike;
/**
 * Build a single-use DPoP proof for a RESOURCE request, bound to the access token via `ath`.
 * Delegates entirely to `@jeswr/solid-dpop`'s `createDpopProof` (RFC 9449 §4.2). A fresh `jti`
 * is minted per call, so the proof is single-use; callers MUST NOT reuse it across requests.
 *
 * @param keyPair    the DPoP keypair the access token is bound to (its thumbprint == the `jkt`)
 * @param method     the HTTP method of the resource request
 * @param url        the resource URL (query + fragment are stripped to form `htu`)
 * @param accessToken the access token whose SHA-256 forms the `ath` claim
 * @param nonce      an optional server-supplied DPoP nonce to echo (RFC 9449 §8)
 */
export declare function resourceDpopProof(keyPair: DpopKeyPair, method: string, url: string, accessToken: string, nonce?: string): Promise<string>;
//# sourceMappingURL=dpop.d.ts.map