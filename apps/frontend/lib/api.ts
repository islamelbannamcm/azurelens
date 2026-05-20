// AzureLens — frontend API client (Phase 7 demo mode)
//
// Thin, typed fetch wrapper. The real client lands in Phase 1 with MSAL
// token acquisition, retry policy, and OpenTelemetry tracing; this version
// stays minimal so it's easy to read in review.
//
// Configuration: set `NEXT_PUBLIC_API_BASE_URL` (defaults to
// `http://localhost:8000` for local dev).

import type {
  AssetSummary,
  CampaignExposureSummary,
  ComplianceFrameworkSummary,
  DashboardSummary,
  Finding,
  FindingSummary,
  RecentScanSummary,
  RemediationAction,
  RemediationRoadmapSummary,
  RemediationStatus,
  RemediationTemplate,
  ScanKind,
  ScanSummary,
  Score,
  ScoreHistory,
  ScoreKind,
  ScoreOverview,
  ThreatExposureSummary,
  TopRiskItem,
} from "@/types/domain";

// ---------------------------------------------------------------------------
// Configuration + low-level fetch
// ---------------------------------------------------------------------------

const DEFAULT_BASE_URL = "http://localhost:8000";

/**
 * Resolve the API base URL. Browser-only (uses NEXT_PUBLIC_*).
 * In Phase 1, server-side fetches will use a private DNS / Private Link URL
 * resolved from an environment variable visible only to the server runtime.
 */
function getBaseUrl(): string {
  if (typeof process !== "undefined" && process.env?.NEXT_PUBLIC_API_BASE_URL) {
    return process.env.NEXT_PUBLIC_API_BASE_URL;
  }
  return DEFAULT_BASE_URL;
}

export class ApiError extends Error {
  constructor(
    message: string,
    public readonly status: number,
    public readonly code: string,
    public readonly correlationId: string | null,
    public readonly body: unknown
  ) {
    super(message);
    this.name = "ApiError";
  }
}

interface RequestOptions {
  /** HTTP method; defaults to GET. */
  method?: "GET" | "POST" | "PUT" | "PATCH" | "DELETE";
  /** JSON body (will be stringified). */
  body?: unknown;
  /** Query parameters. */
  query?: Record<string, string | number | boolean | null | undefined>;
  /** AbortSignal (e.g. from React Query). */
  signal?: AbortSignal;
  /** Override headers (auth header is added automatically when available). */
  headers?: Record<string, string>;
  /** Bearer token; Phase 1 wires this through MSAL silent SSO. */
  accessToken?: string | null;
}

async function request<T>(path: string, opts: RequestOptions = {}): Promise<T> {
  const { method = "GET", body, query, signal, headers, accessToken } = opts;

  let url = `${getBaseUrl()}${path}`;
  if (query) {
    const params = new URLSearchParams();
    for (const [k, v] of Object.entries(query)) {
      if (v === null || v === undefined) continue;
      params.append(k, String(v));
    }
    const qs = params.toString();
    if (qs) url += `?${qs}`;
  }

  const init: RequestInit = {
    method,
    signal,
    headers: {
      Accept: "application/json",
      ...(body !== undefined ? { "Content-Type": "application/json" } : {}),
      ...(accessToken ? { Authorization: `Bearer ${accessToken}` } : {}),
      ...(headers ?? {}),
    },
  };
  if (body !== undefined) {
    init.body = JSON.stringify(body);
  }

  const response = await fetch(url, init);
  const correlationId = response.headers.get("x-correlation-id");

  if (!response.ok) {
    let parsed: unknown = null;
    try {
      parsed = await response.json();
    } catch {
      /* not JSON */
    }
    const detail =
      typeof parsed === "object" && parsed !== null && "detail" in parsed
        ? String((parsed as { detail: unknown }).detail)
        : `HTTP ${response.status}`;
    const code =
      typeof parsed === "object" && parsed !== null && "code" in parsed
        ? String((parsed as { code: unknown }).code)
        : `http_${response.status}`;
    throw new ApiError(detail, response.status, code, correlationId, parsed);
  }

  // 204 No Content
  if (response.status === 204) {
    return undefined as unknown as T;
  }
  return (await response.json()) as T;
}

// ---------------------------------------------------------------------------
// Meta
// ---------------------------------------------------------------------------

export function getHealth(opts: RequestOptions = {}): Promise<{ status: string }> {
  return request<{ status: string }>("/api/v1/health", opts);
}

// ---------------------------------------------------------------------------
// Dashboard
// ---------------------------------------------------------------------------

export function getDashboardSummary(opts: RequestOptions = {}): Promise<DashboardSummary> {
  return request<DashboardSummary>("/api/v1/dashboard/summary", opts);
}

export function getPostureSummary(opts: RequestOptions = {}) {
  return request<DashboardSummary["overall"]>("/api/v1/dashboard/posture-summary", opts);
}

export function getTopRisks(
  limit: number = 5,
  opts: RequestOptions = {}
): Promise<TopRiskItem[]> {
  return request<TopRiskItem[]>("/api/v1/dashboard/top-risks", {
    ...opts,
    query: { ...(opts.query ?? {}), limit },
  });
}

export function getThreatExposureSummary(
  opts: RequestOptions = {}
): Promise<ThreatExposureSummary> {
  return request<ThreatExposureSummary>("/api/v1/dashboard/threat-exposure-summary", opts);
}

export function getComplianceSummary(
  opts: RequestOptions = {}
): Promise<ComplianceFrameworkSummary[]> {
  return request<ComplianceFrameworkSummary[]>("/api/v1/dashboard/compliance-summary", opts);
}

export function getRecentScan(opts: RequestOptions = {}): Promise<RecentScanSummary> {
  return request<RecentScanSummary>("/api/v1/dashboard/recent-scan", opts);
}

export function getRemediationRoadmap(
  opts: RequestOptions = {}
): Promise<RemediationRoadmapSummary> {
  return request<RemediationRoadmapSummary>("/api/v1/dashboard/remediation-roadmap", opts);
}

// ---------------------------------------------------------------------------
// Scores
// ---------------------------------------------------------------------------

export function listScores(opts: RequestOptions = {}): Promise<Score[]> {
  return request<Score[]>("/api/v1/scores", opts);
}

export function getScoreOverview(opts: RequestOptions = {}): Promise<ScoreOverview> {
  return request<ScoreOverview>("/api/v1/scores/overview", opts);
}

export function getScore(kind: ScoreKind, opts: RequestOptions = {}): Promise<Score> {
  return request<Score>(`/api/v1/scores/${kind}`, opts);
}

export function getScoreHistory(
  kind: ScoreKind,
  days: number = 14,
  opts: RequestOptions = {}
): Promise<ScoreHistory> {
  return request<ScoreHistory>(`/api/v1/scores/${kind}/history`, {
    ...opts,
    query: { ...(opts.query ?? {}), days },
  });
}

// ---------------------------------------------------------------------------
// Findings
// ---------------------------------------------------------------------------

export interface FindingsListParams {
  severity?: string;
  status?: string;
  asset_id?: string;
  mitre_technique?: string;
  framework?: string;
  cursor?: string;
  limit?: number;
}

export function listFindings(
  params: FindingsListParams = {},
  opts: RequestOptions = {}
): Promise<{ items: FindingSummary[]; page: { next_cursor: string | null; total_estimate: number | null } }> {
  return request("/api/v1/findings", { ...opts, query: { ...(opts.query ?? {}), ...params } });
}

export function getFinding(findingId: string, opts: RequestOptions = {}): Promise<Finding> {
  return request<Finding>(`/api/v1/findings/${findingId}`, opts);
}

export function acknowledgeFinding(
  findingId: string,
  body: { note?: string; suppress_until?: string | null } = {},
  opts: RequestOptions = {}
): Promise<Finding> {
  return request<Finding>(`/api/v1/findings/${findingId}/acknowledge`, {
    ...opts,
    method: "POST",
    body,
  });
}

// ---------------------------------------------------------------------------
// Assets
// ---------------------------------------------------------------------------

export interface AssetsListParams {
  provider?: string;
  asset_kind?: string;
  exposure?: string;
  criticality?: string;
  cursor?: string;
  limit?: number;
}

export function listAssets(
  params: AssetsListParams = {},
  opts: RequestOptions = {}
): Promise<{ items: AssetSummary[]; page: { next_cursor: string | null; total_estimate: number | null } }> {
  return request("/api/v1/assets", { ...opts, query: { ...(opts.query ?? {}), ...params } });
}

// ---------------------------------------------------------------------------
// Threat intel
// ---------------------------------------------------------------------------

export function listCampaignExposure(
  opts: RequestOptions = {}
): Promise<CampaignExposureSummary[]> {
  return request<CampaignExposureSummary[]>("/api/v1/threat-intel/exposure/campaigns", opts);
}

// ---------------------------------------------------------------------------
// Scans
// ---------------------------------------------------------------------------

export function listScans(opts: RequestOptions = {}): Promise<ScanSummary[]> {
  return request<ScanSummary[]>("/api/v1/scans", opts);
}

export function getScan(scanId: string, opts: RequestOptions = {}): Promise<ScanSummary> {
  return request<ScanSummary>(`/api/v1/scans/${scanId}`, opts);
}

export function getRecentScanSummary(opts: RequestOptions = {}): Promise<RecentScanSummary> {
  return request<RecentScanSummary>("/api/v1/scans/recent", opts);
}

export function triggerScan(
  body: { kinds?: ScanKind[]; trigger_type?: string } = {},
  opts: RequestOptions = {}
): Promise<ScanSummary> {
  // The demo endpoint synthesizes a queued scan; Phase 1 publishes to Service Bus.
  return request<ScanSummary>("/api/v1/scans", { ...opts, method: "POST", body });
}

// ---------------------------------------------------------------------------
// Remediations
// ---------------------------------------------------------------------------

export interface RemediationListParams {
  status?: RemediationStatus;
}

export function listRemediations(
  params: RemediationListParams = {},
  opts: RequestOptions = {}
): Promise<RemediationAction[]> {
  return request<RemediationAction[]>("/api/v1/remediations", {
    ...opts,
    query: { ...(opts.query ?? {}), ...params },
  });
}

export function listRemediationTemplates(
  opts: RequestOptions = {}
): Promise<RemediationTemplate[]> {
  return request<RemediationTemplate[]>("/api/v1/remediations/templates", opts);
}

export function getRemediationRoadmapDetail(
  opts: RequestOptions = {}
): Promise<RemediationRoadmapSummary> {
  return request<RemediationRoadmapSummary>("/api/v1/remediations/roadmap", opts);
}

export function getRemediationAction(
  actionId: string,
  opts: RequestOptions = {}
): Promise<RemediationAction> {
  return request<RemediationAction>(`/api/v1/remediations/${actionId}`, opts);
}

export function approveRemediation(
  actionId: string,
  opts: RequestOptions = {}
): Promise<RemediationAction> {
  return request<RemediationAction>(`/api/v1/remediations/${actionId}/approve`, {
    ...opts,
    method: "POST",
  });
}

// ---------------------------------------------------------------------------
// Re-exports for ergonomic consumer imports
// ---------------------------------------------------------------------------

export type {
  AssetSummary,
  CampaignExposureSummary,
  ComplianceFrameworkSummary,
  DashboardSummary,
  Finding,
  FindingSummary,
  RecentScanSummary,
  RemediationAction,
  RemediationRoadmapSummary,
  RemediationTemplate,
  ScanSummary,
  Score,
  ScoreHistory,
  ScoreOverview,
  ThreatExposureSummary,
  TopRiskItem,
};
