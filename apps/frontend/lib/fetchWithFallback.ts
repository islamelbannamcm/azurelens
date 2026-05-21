// Phase 11 — generic fetcher with a 2.5s timeout and a typed fallback.
//
// Wraps any async API client call (e.g. `getDashboardSummary`, `listScans`)
// so a page renders the live response when the API is reachable, and the
// local demo dataset otherwise. The reason string is suitable for a banner
// ("HTTP 503", "timed out after 2.5s", "network unreachable", …).
//
// Server-component-safe; only depends on `fetch`, `AbortController`, and
// `lib/api.ts::ApiError`.

import { ApiError } from "@/lib/api";

const DEFAULT_TIMEOUT_MS = 2_500;

export interface FetchOutcome<T> {
  data: T;
  usingFallback: boolean;
  fallbackReason?: string;
}

export interface FetchWithFallbackOptions<T> {
  /** Async fetcher; receives an AbortSignal it should forward to the API. */
  fetcher: (signal: AbortSignal) => Promise<T>;
  /** Used when the fetcher rejects, throws, or aborts. */
  fallback: T;
  /** Override the default 2.5s timeout. */
  timeoutMs?: number;
}

export async function fetchWithFallback<T>({
  fetcher,
  fallback,
  timeoutMs = DEFAULT_TIMEOUT_MS,
}: FetchWithFallbackOptions<T>): Promise<FetchOutcome<T>> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const data = await fetcher(controller.signal);
    return { data, usingFallback: false };
  } catch (err) {
    return { data: fallback, usingFallback: true, fallbackReason: describe(err, timeoutMs) };
  } finally {
    clearTimeout(timer);
  }
}

function describe(err: unknown, timeoutMs: number): string {
  if (err instanceof ApiError) return `HTTP ${err.status} (${err.code})`;
  if (err instanceof DOMException && err.name === "AbortError") {
    return `timed out after ${(timeoutMs / 1000).toFixed(1)}s`;
  }
  // Native fetch reports network failure (ECONNREFUSED, DNS, etc.) as TypeError.
  if (err instanceof TypeError) return "network unreachable";
  if (err instanceof Error) return err.message;
  return "unknown error";
}
