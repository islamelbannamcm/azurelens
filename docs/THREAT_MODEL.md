# AzureLens — Threat Model

STRIDE-based threat model with explicit **trust boundaries**, per-component analysis, **AI-specific** (OWASP LLM Top 10) and **multi-tenant** threats, abuse cases, and mitigations.

> Updated alongside architecture changes. Each new component added in a feature branch must extend this model.

---

## 1. Methodology

- **STRIDE**: Spoofing, Tampering, Repudiation, Information disclosure, Denial of service, Elevation of privilege.
- **MITRE ATT&CK for Enterprise/Cloud** as the adversary technique reference.
- **OWASP Top 10 for LLM Applications** for the AI engine.
- **Abuse cases** for multi-tenant SaaS (cross-tenant access, billing abuse, supply-chain poisoning).

Scope: AzureLens platform itself (its own infrastructure, code, identities, and data plane). We are explicitly **not** threat-modeling the *customer* tenant here — that's the platform's job to do continuously for the customer.

---

## 2. Assets

| Asset | Sensitivity | Owner |
|---|---|---|
| Customer tenant identifiers, names, domains | Moderate | Customer |
| Customer user / device / resource inventories | Moderate | Customer |
| Customer posture findings & scores | Moderate-High | Customer |
| Customer audit logs imported from Microsoft Graph / Sentinel | High | Customer |
| Raw scan evidence (JSON snapshots) | High | Customer |
| Customer connector secrets (MISP/OTX/VT API keys) | High | Customer |
| Platform Entra ID multi-tenant app credentials | Critical | Platform |
| Platform CMK / encryption keys | Critical | Platform / Customer (per tier) |
| AI prompt + response logs | High | Customer (data) + Platform (operations) |
| Reference framework packs | Low (integrity-sensitive) | Platform |
| Threat intelligence corpus | Low-Moderate (some commercial) | Platform |

---

## 3. Trust Boundaries

```
[ Internet ] ─┬─ TB1 ─► [ Front Door + WAF ]
              │                 │
              └─ TB1 ─► [ Customer Microsoft tenant ] (data source)
                                │
                                ▼  (outbound auth'd calls)
[ Hub VNet egress ] ── TB2 ──► [ Microsoft Graph / ARM / Defender / Sentinel / Purview ]

[ Front Door ] ── TB3 ──► [ APIM (internal) ] ── TB4 ──► [ API Container Apps ]
                                                              │
                                  ┌──────────────── TB5 ──────┤
                                  ▼                            ▼
                          [ Data plane: SQL,            [ Async backbone:
                            Cosmos, Storage,             Service Bus, Event Grid,
                            Key Vault, AI Search,        Event Hubs ]
                            OpenAI ]                     │
                                                          ▼
                                                  [ Worker tier:
                                                    Scanners, TI, AI,
                                                    Reporting, Notification ]
                                                          │
                                                          ▼  (outbound)
                                                  [ TB6: TI sources (CISA, MITRE,
                                                    MISP, OpenCTI, OTX, abuse.ch,
                                                    GHSA, NVD, VT) ]

[ GitHub Actions ] ── TB7 ──► [ Azure subscriptions ] (OIDC)
[ Platform operators ] ── TB8 ──► [ Azure portal / Bastion / break-glass ]
[ AI prompts ] ── TB9 ──► [ Azure OpenAI ]
[ Tenant A data ] ── TB10 ──► [ Tenant B isolation boundary ]
```

| TB | From → To | Authn | Authz |
|---|---|---|---|
| TB1 | Internet → Front Door | TLS 1.2+ | WAF / bot mgmt |
| TB2 | Egress → Microsoft APIs | App registration (cert) / Managed Identity / OBO | Per-permission consent |
| TB3 | Front Door → APIM | mTLS + FD-id header | Private Link only |
| TB4 | APIM → API | Managed Identity | Subscription key + quota |
| TB5 | API → Data plane | Managed Identity (Entra AD auth) | RBAC scoped to tenant |
| TB6 | Workers → TI sources | API keys (KV) / unauth public | Trust-score weighting |
| TB7 | GitHub → Azure | OIDC federation (no PAT) | Per-env RBAC |
| TB8 | Operator → Azure | Entra ID + MFA + PIM | JIT activation, audited |
| TB9 | API/Workers → Azure OpenAI | Managed Identity | Per-deployment RBAC |
| TB10 | Tenant A → Tenant B | (must never happen) | Row-level security + partition filter |

---

## 4. STRIDE per Component

### 4.1 Frontend (`apps/web`)

| Threat | STRIDE | Mitigation |
|---|---|---|
| Token theft via XSS | S, I | Strict CSP, no inline scripts, MSAL with in-memory tokens, sanitization, Trusted Types |
| Clickjacking | T | `X-Frame-Options: DENY`, frame-ancestors CSP |
| Cookie theft | I | SameSite=Strict, Secure, HttpOnly cookies |
| Supply-chain (npm) | T | Lockfile + integrity hashes, Dependabot, signed releases, internal proxy registry |
| Brand spoofing (lookalike domains) | S | Domain monitoring + DMARC/SPF/DKIM on platform mail |

### 4.2 Backend API (`apps/api`)

| Threat | STRIDE | Mitigation |
|---|---|---|
| Auth bypass via token forgery | S | Strict JWT validation (issuer, audience, signing keys via JWKS w/ rotation) |
| **Cross-tenant data access** | I, E | Mandatory tenant filter middleware + SQL row-level security + automated CI isolation tests |
| IDOR | E, I | Resource-id ownership check on every read/write |
| Mass assignment | T | DTO allowlists; no entity binding |
| SSRF in connector configuration | I | URL allowlist + DNS rebinding protection + outbound firewall |
| GraphQL introspection abuse | I | Disable introspection in prod, depth + complexity limits |
| Rate-based DoS | D | APIM quotas + Front Door rate limiting |

### 4.3 Scanner workers

| Threat | STRIDE | Mitigation |
|---|---|---|
| Malicious response from Microsoft API (man-in-the-middle) | T, I | TLS 1.2+, cert pinning to Microsoft PKI, response schema validation |
| Excessive Graph calls → tenant throttling | D | Per-tenant token-bucket, backoff, circuit breaker |
| Storage of secrets in scan evidence | I | Evidence sanitizer strips known secret patterns before persisting |
| Stuck or replayed jobs | T, D | Idempotency keys, dead-letter queue, max-attempts, monotonic clock fences |
| Privileged write performed accidentally | E | Read-only RBAC enforced; remediation SP separate and opt-in |

### 4.4 Threat Intelligence Ingestion

| Threat | STRIDE | Mitigation |
|---|---|---|
| TI feed compromise (malicious IoC injection) | T, I | Source trust scoring, anomaly detection on indicator-volume spikes, manual review for trust-elevating changes |
| Feed serves malicious payload | T | Sandboxed parsing, hard size limits, AV scan on raw blobs in ADLS |
| Feed source DoS / outage | D | Cached last-known-good, graceful degradation, per-source health metric |
| Stale TI data → false negatives | I | Freshness SLO + alerting per source |
| Sensitive customer query leaking to TI source (e.g., VT lookup) | I | Hash-only lookups for VT; never send customer-identifying data to public TI sources |

### 4.5 AI Engine (OWASP LLM Top 10)

| OWASP | Threat | Mitigation |
|---|---|---|
| LLM01 | Prompt injection (via finding text, TI text, user prompt) | Input sanitization, system-prompt isolation, instruction hierarchy, output classifiers, refusal on conflicting instructions |
| LLM02 | Insecure output handling | JSON-schema validation; never execute LLM output as code without explicit allowlisted tool-call schema |
| LLM03 | Training data poisoning | N/A — no fine-tuning on customer data; reference packs are signed and version-pinned |
| LLM04 | Model DoS | Per-tenant token quotas, max prompt length, request concurrency limits |
| LLM05 | Supply chain | Pin model versions; use Azure OpenAI deployments only |
| LLM06 | Sensitive info disclosure | PII redaction before prompts; per-tenant RAG isolation; output PII scrub |
| LLM07 | Insecure plugin/tool use | Tool-use schemas validated; tools side-effect-free in default mode |
| LLM08 | Excessive agency | No autonomous remediation; AI may *suggest* but not *execute* by default |
| LLM09 | Overreliance | Every AI output cites underlying structured findings; users see source data |
| LLM10 | Model theft | N/A (consumed via Azure OpenAI), but: audit of all calls, anomaly detection on token consumption |

### 4.6 Data Stores

| Threat | STRIDE | Mitigation |
|---|---|---|
| Storage account public exposure | I | Network rules deny public; Private Endpoint only; Defender for Storage alerts |
| KV secret exfiltration | I | RBAC + soft-delete + purge protection + alert on any unauthorized `getSecret` |
| SQL injection | T, I | Parameterized queries only; ORM with safe defaults; static analysis |
| Cosmos partition cross-read | I | RBAC data-plane; query template enforces `tenant_id` partition key |
| Backup tampering | T | Immutable backup vault; separate CMK; restore drills |
| Ransomware on Storage | T, D | Versioning + soft delete + immutability policy + Defender for Storage |

### 4.7 Eventing

| Threat | STRIDE | Mitigation |
|---|---|---|
| Event replay attack | T | Idempotency keys + dedupe table |
| Cross-tenant event leakage | I | Subscription filters on `tenant_id`; per-tenant sessions where ordering matters |
| Poison messages | D | DLQ + max-delivery-count + automated re-drive with quarantine |
| Schema drift breaks consumers | T | Versioned schemas; consumers tolerate forward/backward compatibility |

### 4.8 CI/CD

| Threat | STRIDE | Mitigation |
|---|---|---|
| Compromised GitHub Actions runner injects malicious deploy | T, E | OIDC federation (no long-lived secrets), required signed commits, environment protection rules, mandatory reviews on workflow changes |
| Dependency confusion / typosquatting | T | Internal package proxy; lockfiles; provenance attestations (SLSA) |
| Container image tampering | T | ACR + Cosign signing; admission policy verifies signatures |
| Secrets leakage in pipeline logs | I | Masked secrets, log scrubbers, GHAS secret scanning |
| Build supply chain (e.g., compromised base image) | T | Pinned digests; periodic rebase with diffing; vuln scan in CI |

### 4.9 Identity & RBAC

| Threat | STRIDE | Mitigation |
|---|---|---|
| Token replay | S | Short-lived tokens, refresh rotation, audience binding |
| MFA bypass / SIM-swap | S | Entra ID phishing-resistant MFA (FIDO2) required for admins |
| Standing privileged access | E | PIM eligibility only; JIT activation with MFA + justification |
| App-role abuse via inflated claims | E | Server-side authorization checks; never trust client-claimed roles outside JWT |
| Break-glass account misuse | E | Sealed credentials, monitored, alert on use, quarterly rotation |

### 4.10 Network

| Threat | STRIDE | Mitigation |
|---|---|---|
| DDoS on public endpoint | D | Front Door + DDoS Standard |
| Data exfiltration via outbound | I | Azure Firewall FQDN allowlist, deny-by-default egress |
| Lateral movement after compromise | E | NSG segmentation, ASGs, Private Endpoints, no shared service principals |
| DNS hijacking | T, S | Private DNS zones; Azure DNS DNSSEC where applicable; pinned resolvers |

### 4.11 Customer-tenant operations (out-bound)

| Threat | STRIDE | Mitigation |
|---|---|---|
| Compromise of platform multi-tenant app → mass customer impact | E | Cert-based auth (no client secret), short-lived assertions, hardware-protected key, anomaly detection on token-issuance patterns, per-tenant kill switch (revoke consent) |
| Customer admin tricked into granting excessive consent | E | Permission catalog UX, modular consent, default-minimum scopes |
| Customer firewalls block egress | D | Documented platform egress IP ranges; health checks |

---

## 5. Multi-Tenant Abuse Cases

| Abuse | Vector | Mitigation |
|---|---|---|
| Tenant A reads Tenant B data via crafted ID | API IDOR | Mandatory tenant filter + RLS + CI isolation tests |
| Tenant A exhausts shared compute → noisy neighbor | Excessive scans/AI usage | Per-tenant quotas, KEDA-based autoscale, queue-per-tenant for fairness |
| Tenant A injects data into shared TI/AI corpus | Connector / API write | Per-tenant TI store; no shared write |
| Billing abuse (free-tier scan loops) | Repeated onboarding | Tenant-id verification (Entra), payment method on Pro+, abuse detection |
| Side-channel timing inference | Shared workers | Constant-time auth checks; no error messages that leak existence |

---

## 6. Adversary Profiles

| Adversary | Motivation | Likely techniques |
|---|---|---|
| **Opportunistic ransomware actor** | Financial | Exposed endpoints, exposed credentials in CI/CD |
| **Targeted threat actor** (APT) | Espionage / IP | Phishing platform operators, supply-chain compromise, consent phishing on the multi-tenant app |
| **Insider (platform operator)** | Curiosity / malice | Read customer findings, exfil via screenshot or backup |
| **Compromised customer admin** | Lateral via the platform | Abuse legitimate consent to enumerate the platform |
| **Hacktivist** | Reputation damage | Public-facing endpoint DoS, defacement attempts |
| **Compromised TI source** | Supply chain | Poison the TI corpus |
| **Curious researcher / bounty hunter** | Recognition | Boundary probing, IDOR fuzzing |

---

## 7. Risk Register (top items)

| ID | Risk | Likelihood | Impact | Mitigation priority |
|---|---|---|---|---|
| R-1 | Cross-tenant data leak via API bug | Low | Critical | Highest — defense in depth + CI tests + RLS |
| R-2 | Compromise of multi-tenant app credential | Low | Critical | Hardware-protected cert, anomaly detection, kill switch |
| R-3 | Prompt-injection in AI engine causes data leak | Medium | High | Sanitization, isolation, output guards, citations |
| R-4 | TI feed poisoning skews customer risk scores | Low | Medium | Source trust weighting, anomaly detection, review gates |
| R-5 | Insider operator reads customer data | Low | High | PIM JIT, all-read audit, alerts on bulk reads |
| R-6 | Supply-chain (npm / NuGet / pip / base image) | Medium | High | Lockfiles, internal proxy, signing, SBOM, GHAS |
| R-7 | DoS on public ingress | Medium | Medium | WAF, DDoS, rate limiting, autoscale |
| R-8 | Misconfigured CMK breaks tenant access | Low | High | Rotation drills, key-version retention, alerts on KV access |
| R-9 | Long-running scan ↔ Graph throttling causes false negatives | Medium | Medium | Per-tenant rate limiter, scan completeness SLO + alerts |
| R-10 | Customer revokes consent mid-scan → partial data | High | Low | Detect 401/403, mark scan partial, notify customer admin |

---

## 8. Mitigations Catalog (cross-cutting)

- **Identity**: Managed Identity everywhere, Entra ID phishing-resistant MFA for admins, PIM JIT, no standing privilege.
- **Network**: WAF, Private Endpoints, Azure Firewall egress allowlist, NSG deny-by-default.
- **Data**: CMK (per-tenant in Enterprise), immutability for evidence, soft-delete + purge protection on KV.
- **Code**: SAST (CodeQL), DAST in staging, dependency scanning, SBOM, signed images, signed Bicep releases.
- **Runtime**: Defender for Cloud Plans P2 enabled on all subscriptions; Defender for Containers; Defender for DevOps.
- **Observability**: Sentinel analytics rules tuned to platform telemetry; auto-incident on cross-tenant attempts, KV anomalies, mass-export events.
- **Process**: quarterly threat model refresh, annual external pen-test, monthly security drills (incident, restore, isolation).

---

## 9. Things This Model Does Not Cover (Yet)

- Customer-hosted mode-specific threats (customer subscription compromise drag-in) — addressed in Phase 8 doc.
- Cross-region failover during active attack — addressed in DR runbook.
- Quantum-readiness for KMS — tracked separately; revisit when Azure publishes PQC roadmap.
- Sovereign-cloud variants (Gov, China) — separate threat model when those are in scope.

---

*Every architectural change must answer: which trust boundary does this cross, which STRIDE threats does it introduce or modify, and what mitigations apply? Recorded as an ADR with a link back to the relevant section of this document.*
