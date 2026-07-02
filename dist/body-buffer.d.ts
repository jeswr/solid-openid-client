/**
 * Replayable-request-body primitive for the authed `fetch`.
 *
 * The RFC 9449 §8 DPoP-nonce retry re-sends the SAME request after a challenge, so a stream body
 * must be buffered ONCE up front or the retry would send an empty/locked body. This module owns
 * that buffering, INCLUDING its two hard invariants (essential concurrency/memory-safety complexity
 * — deliberately NOT flattened; a reviewer audits it here, once, with its dedicated tests):
 *
 *   - ABORT-CORRECTNESS — an `AbortSignal` firing mid-read must reject promptly AND actually cancel
 *     the underlying source (we read via our own `getReader()`, never `new Response(stream)`, whose
 *     `arrayBuffer()` locks the reader so `cancel()` can no longer stop a never-ending stream).
 *   - BOUNDED MEMORY — a stream larger than `maxBytes` is REJECTED (and the reader cancelled), so an
 *     unbounded upload cannot exhaust memory.
 *
 * Pure/self-contained: no I/O beyond reading the caller-supplied stream, no package state.
 */
/**
 * Default cap (bytes) on a STREAM request body buffered for §8 nonce-retry replay. A stream body
 * larger than this is rejected rather than buffered (so an upload cannot exhaust memory). 10 MiB —
 * generous for typical Solid resource writes; raise via `maxReplayBodyBytes` for larger uploads.
 */
export declare const DEFAULT_MAX_REPLAY_BODY_BYTES: number;
/**
 * Buffer a body into a REPLAYABLE form. A `ReadableStream` is read once into an `ArrayBuffer` so
 * it can be sent on both the original attempt and the §8 nonce retry; all other `BodyInit` values
 * (string / `Uint8Array` / `Blob` / `URLSearchParams` / `FormData` / `ArrayBuffer`) are already
 * replayable and pass through unchanged. `null`/`undefined` → `undefined`. An `AbortSignal`, when
 * supplied, aborts an in-flight stream read promptly (matching `fetch` abort semantics).
 *
 * `maxBytes` caps the buffered size so a large/unbounded stream upload cannot exhaust memory (a
 * roborev finding): a stream body larger than the cap is REJECTED rather than buffered. To upload a
 * body larger than the cap, raise `maxReplayBodyBytes` (or pass a non-stream body, which is not
 * buffered).
 */
export declare function bufferBody(body: BodyInit | null | undefined, signal: AbortSignal | undefined, maxBytes: number): Promise<BodyInit | undefined>;
/**
 * Drain a `ReadableStream<Uint8Array>` to a single `Uint8Array`, honouring an optional
 * `AbortSignal`. We read MANUALLY via `stream.getReader()` (NOT `new Response(stream).arrayBuffer()`)
 * because `arrayBuffer()` locks the stream's reader, after which `stream.cancel()` throws and the
 * in-flight read is NOT cancelled — a never-ending stream would keep draining in the background
 * even after our promise rejected (a roborev finding). With our own reader we can `reader.cancel()`
 * on abort, which actually stops the active read. Each `reader.read()` is raced against the abort
 * so an abort mid-chunk rejects promptly.
 */
export declare function readStreamWithSignal(stream: ReadableStream<Uint8Array>, signal: AbortSignal | undefined, maxBytes: number): Promise<ArrayBuffer>;
/** The abort reason if the signal supplies one, else a standard `AbortError`. */
export declare function abortReason(signal: AbortSignal): unknown;
//# sourceMappingURL=body-buffer.d.ts.map