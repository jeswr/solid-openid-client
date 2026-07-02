// AUTHORED-BY Claude Opus 4.8 (Fable unavailable) — re-review/upgrade candidate
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
export const DEFAULT_MAX_REPLAY_BODY_BYTES = 10 * 1024 * 1024;

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
export async function bufferBody(
  body: BodyInit | null | undefined,
  signal: AbortSignal | undefined,
  maxBytes: number,
): Promise<BodyInit | undefined> {
  if (body === null || body === undefined) {
    return undefined;
  }
  if (body instanceof ReadableStream) {
    return readStreamWithSignal(body, signal, maxBytes);
  }
  return body;
}

/**
 * Drain a `ReadableStream<Uint8Array>` to a single `Uint8Array`, honouring an optional
 * `AbortSignal`. We read MANUALLY via `stream.getReader()` (NOT `new Response(stream).arrayBuffer()`)
 * because `arrayBuffer()` locks the stream's reader, after which `stream.cancel()` throws and the
 * in-flight read is NOT cancelled — a never-ending stream would keep draining in the background
 * even after our promise rejected (a roborev finding). With our own reader we can `reader.cancel()`
 * on abort, which actually stops the active read. Each `reader.read()` is raced against the abort
 * so an abort mid-chunk rejects promptly.
 */
export async function readStreamWithSignal(
  stream: ReadableStream<Uint8Array>,
  signal: AbortSignal | undefined,
  maxBytes: number,
): Promise<ArrayBuffer> {
  const reader = stream.getReader();

  // ONE abort listener for the whole read (not one per chunk). `abortRace` is a single promise
  // that rejects when the signal fires; it is reused across every `reader.read()`. The listener is
  // removed in the `finally` below, so a long multi-chunk read does not accumulate stale listeners
  // (a roborev finding).
  let removeAbortListener: (() => void) | undefined;
  const abortRace: Promise<never> | undefined =
    signal === undefined
      ? undefined
      : new Promise<never>((_resolve, reject) => {
          const onAbort = () => reject(abortReason(signal));
          signal.addEventListener("abort", onAbort, { once: true });
          removeAbortListener = () => signal.removeEventListener("abort", onAbort);
        });
  // Swallow the abortRace rejection if it never wins the race (avoids an unhandled rejection when
  // the read completes first and we stop awaiting it).
  abortRace?.catch(() => {});

  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    // Route the already-aborted case through the same try/finally so the lock is always released.
    if (signal?.aborted) {
      throw abortReason(signal);
    }
    for (;;) {
      const result = abortRace
        ? await Promise.race([reader.read(), abortRace])
        : await reader.read();
      if (result.done) {
        break;
      }
      total += result.value.byteLength;
      // Bounded buffering: a body larger than the cap is rejected (cancels the reader) rather than
      // buffered, so a large/unbounded upload cannot exhaust memory.
      if (total > maxBytes) {
        throw new Error(
          `authedFetch: request stream body exceeds the ${maxBytes}-byte replay buffer cap. ` +
            "Raise `maxReplayBodyBytes` to upload a larger body (it is buffered so the §8 DPoP-nonce " +
            "retry can replay it).",
        );
      }
      chunks.push(result.value);
    }
  } catch (err) {
    // On abort (or any read error) cancel the reader so the source stops producing, then rethrow.
    await reader.cancel(err).catch(() => {});
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
  // Return an ArrayBuffer (a `BodyInit`/`BufferSource`) sized exactly to the bytes read.
  return out.buffer.slice(0, total);
}

/** The abort reason if the signal supplies one, else a standard `AbortError`. */
export function abortReason(signal: AbortSignal): unknown {
  const reason = (signal as { reason?: unknown }).reason;
  if (reason !== undefined) {
    return reason;
  }
  return new DOMException("The operation was aborted.", "AbortError");
}
