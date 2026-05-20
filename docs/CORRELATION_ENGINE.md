# AzureLens — Correlation Engine

How live threat intelligence is mapped to a tenant's Azure, Microsoft 365, Entra ID, Intune, Defender, Sentinel, Purview, and compliance posture. This is the difference between *"here are 10,000 IOCs in the world"* and *"this specific campaign hits 3 of your VMs and 42 of your privileged identities."*

> Foundation note: Phase 4 introduces the contracts. Real matching runs in Phase 2 (basic) and Phase 4 (full). See `docs/THREAT_INTEL_ARCHITECTURE.md` for the corpus side and `docs/SCANNER_ARCHITECTURE.md` for the posture side.

---

## 1. What the correlator does

Given:

- the **shared TI corpus** (KEV, MITRE, Defender TI, Sentinel TI, MISP, OpenCTI, OTX, abuse.ch, GHSA, NVD, tenant-private TI), and
- a tenant's **asset graph + findings + telemetry + profile**,

the correlator produces `CorrelationCandidate` records along well-defined `CorrelationDimension`s:

| Dimension | Joins | Outcome |
|---|---|---|
| `cve_in_inventory` | `Vulnerability.affected_cpes` ⨝ `Asset.cpe_strings` | CVE→VM image / AKS node / Intune device / package match |
| `ip_in_nsg` | `Indicator.value (ipv4/ipv6)` ⨝ NSG/AppGW/FW flow logs | Known-bad IP touching tenant edge |
| `domain_in_traffic` | `Indicator.value (domain)` ⨝ Sentinel / Defender XDR DNS | Known-bad domain in tenant traffic |
| `url_in_traffic` | `Indicator.value (url)` ⨝ M365 audit + Defender XDR proxy | Known-bad URL in tenant traffic |
| `technique_to_finding` | `AttackPattern.technique_id` ⨝ `Finding.mitre_techniques` | Active TTP applies to a real gap on this tenant |
| `sector_alignment` | `Campaign.target_sectors / geographies` ⨝ `TenantProfile` | Tenant is in scope of an active campaign |
| `platform_match` | `Campaign` underlying `Tool` / `Malware` platform ⨝ tech stack | Campaign matches tenant tech |
| `malware_family_to_posture` | `Malware family` ⨝ posture conditions that enable it | Posture gaps line up with how this family operates |

The result of each pass is one `CorrelationResult` per tenant per dimension, containing zero-or-more `CorrelationCandidate`s. Confidence is reported in `[0, 100]` along with structured `evidence`.

---

## 2. How findings change when a correlation hits

A correlation hit doesn't create a new finding by itself — it **boosts** an existing finding's risk and **enriches** the narrative:

- **Risk Engine** (`services/risk-engine`) multiplies `campaign_proximity_factor` (default ×1.4) and `exploitability_factor` (default ×1.5 on active KEV) into the finding's risk score.
- **AI Engine** (`services/ai-engine`) picks up the hit as grounding material for the *campaign briefing* and *executive narrative* prompts, citing the specific campaign / actor / malware family.
- **Remediation Center** (`services/remediation`) re-prioritizes the backlog so findings tied to active campaigns float to the top.
- **API**: surfaced via `GET /api/v1/threat-intel/correlations` and `GET /api/v1/threat-intel/exposure/campaigns`.

A hit never *invents* posture data; it only re-ranks and re-explains it.

---

## 3. Per-source-of-posture mapping

How each AzureLens posture source contributes the *right side* of the join:

### 3.1 Azure (via `scanner-azure` / Azure Resource Graph)

| Used for | Posture inputs |
|---|---|
| `cve_in_inventory` | `azure.vm.image_publisher/offer/sku/version`, `azure.aks` node images, container image inventory |
| `ip_in_nsg` | `azure.nsg` rule sources + `azure.public_ip`s, App Gateway / Front Door / Firewall logs (via LAW) |
| `technique_to_finding` | Posture findings (`T1078` from PIM gaps, `T1190` from public app surface, `T1078.004` from broad RBAC, ...) |
| `malware_family_to_posture` | Open ports, missing Defender for Servers / Containers, weak NSGs, no Private Endpoints |

### 3.2 Entra ID / M365 (via `scanner-m365` / `scanner-entra`)

| Used for | Posture inputs |
|---|---|
| `technique_to_finding` | Identity findings: missing MFA (`T1078`), legacy auth allowed (`T1110.003`), broad OAuth consent (`T1528`), unmanaged forwarding (`T1114`) |
| `malware_family_to_posture` | Risky users, permanent Global Admins, unrestricted external collaboration |
| `domain_in_traffic` (M365 side) | Exchange Online sending-domain reputation, suspicious sign-in IPs |

### 3.3 Intune (via `scanner-intune`)

| Used for | Posture inputs |
|---|---|
| `cve_in_inventory` | OS / OS-version / patch-state per device |
| `malware_family_to_posture` | Defender for Endpoint onboarding %, BitLocker enabled, AV on, attack-surface-reduction rules |
| `technique_to_finding` | Findings tagged with techniques the family commonly uses (e.g. `T1486` Impact for ransomware) |

### 3.4 Defender (via `scanner-defender`)

| Used for | Posture inputs |
|---|---|
| `cve_in_inventory` | Defender for Cloud sub-assessments (vulnerability scans on VMs / containers / SQL) |
| `technique_to_finding` | Defender for Cloud recommendations mapped to MCSB → MITRE |
| `ip_in_nsg` / `domain_in_traffic` | Defender XDR alerts already containing IOCs as evidence; we cross-link rather than re-detect |

### 3.5 Sentinel (via `scanner-sentinel` / TI bridge)

| Used for | Posture inputs |
|---|---|
| `ip_in_nsg`, `domain_in_traffic`, `url_in_traffic` | Workspace KQL over network / DNS / proxy / M365 logs |
| `technique_to_finding` | Analytics-rule presence/absence (a missing-detection finding maps to the technique the rule would catch) |

### 3.6 Purview (via `scanner-purview`)

| Used for | Posture inputs |
|---|---|
| `malware_family_to_posture` | DLP coverage, sensitivity labels, retention — proxy for data-exfil resilience |
| `technique_to_finding` | Findings around data exfiltration techniques (`T1567 Exfiltration over Web Service`, `T1530 Data from Cloud Storage`) |

### 3.7 Compliance (via `services/compliance-engine`)

Compliance findings carry the same `mitre_techniques` tags as posture findings, so they participate in `technique_to_finding` unchanged. The crosswalk in `packages/frameworks/` ensures consistent technique tagging across CIS / MCSB / NIST / ISO / SOC2 / GDPR / Zero Trust / Azure WAF / M365 baseline controls.

---

## 4. Worked examples

### 4.1 *"Active phishing wave abuses weak MFA"*

- **Input from TI**: `Campaign` "Storm-XXXX phishing wave Q2-2026" with `techniques=['T1078','T1556.006','T1110']`, `target_sectors=['financial']`, plus `Indicator`s (domains / IPs).
- **Right side of join**:
  - `m365.conditional_access_policy` findings showing CA gaps for privileged users → `technique_to_finding` on `T1078`.
  - `domain_in_traffic` hits from Sentinel DNS logs on the campaign's known domains.
  - `sector_alignment` if `TenantProfile.sectors` contains `financial`.
- **Output**: 3+ `CorrelationCandidate`s pointing at the same set of CA-policy findings. Risk engine boosts the findings; AI engine writes "*This active campaign maps to your X CA gaps; you have already seen Y indicator domains in DNS logs.*"

### 4.2 *"Ransomware campaign abuses public RDP"*

- **Input from TI**: `Campaign` "Akira RDP brute-force wave" with `techniques=['T1133','T1078','T1486']`; `Malware` family "Akira" with `malware_types=['ransomware']`.
- **Right side of join**:
  - `azure.network.rdp_public_exposed` finding on 3 VMs → `technique_to_finding` on `T1133`.
  - `malware_family_to_posture` checks {exposed ports = 3389, EDR onboarded = false on those VMs, backup enabled = false}.
- **Output**: 4+ candidates with high confidence. Remediation Center floats *"Restrict RDP to Azure Bastion"* to the top of the backlog. AI engine writes the executive narrative.

### 4.3 *"CISA KEV CVE actively exploited"*

- **Input from TI**: `Vulnerability` `CVE-2024-XXXXX` with `is_kev=True`, `cvss_v3=9.8`, `epss_score=0.95`, `affected_cpes=[...]`.
- **Right side of join**: Intune device inventory + Azure VM image inventory matches CPE → `cve_in_inventory` candidate.
- **Output**: Findings on affected assets get `exploitability_factor=1.5` boost. AI engine writes *"CISA reports active exploitation; you have 12 affected devices."*

---

## 5. Algorithmic notes

- **CVE↔inventory** is N×M; we build a CPE prefix-tree per tenant and stream vulnerabilities through it. Phase 2 caps tenant size; Phase 4 scales via Cosmos partitioning + parallel partition reads.
- **IOC↔telemetry** is the heaviest pass. We push the IOC list to a per-tenant **KQL function** in Sentinel and let the workspace do the join; we ingest only the matches back, never the raw telemetry. This keeps customer telemetry in-tenant.
- **Technique↔finding** is small and fast — an in-memory index per tenant; recomputed on every `finding.normalized` event.
- **Sector/platform alignment** is constant-time per (tenant, campaign).
- **Malware-family→posture** uses a hand-curated rules pack keyed by family, with TODO(phase-4) gates for adding families as they appear in the wild.

---

## 6. Trust, confidence, and decay

- **Per-source trust** weights the source-provided `confidence` into the candidate's effective confidence.
- **Recency**: indicator hits older than the IOC's `valid_until` (or the source's default decay window — commodity IOCs 30/60/90 days; CVE/KEV never decay) drop in confidence.
- **Multi-source confirmation**: a candidate seen across ≥ 2 independent sources gets a small bump.
- **Customer override**: tenants can pin trust per source (down to 0 to disable a source for their tenant entirely).

---

## 7. Privacy & tenant isolation

The correlator is the place where **shared TI** meets **tenant posture**. We never expose another tenant's posture and we never persist a copy of customer telemetry in the shared corpus:

- The correlator's per-tenant inputs (`AssetView`, `FindingView`, `TenantProfile`) are filtered to `tenant_id` at the source. The correlator additionally re-checks inputs (`_guard_inputs`) and raises `TIIsolationError` on mismatch (P0).
- Results (`CorrelationCandidate`) are written to the tenant-private partition (`tenant_id` as the partition key).
- KQL pushdown into Sentinel keeps the customer's telemetry inside their workspace; only the *match outcomes* come back to AzureLens.
- VirusTotal and other public-source lookups never receive tenant-identifying data — see `docs/THREAT_INTEL_ARCHITECTURE.md` § 8.

---

## 8. Operational properties

- **Idempotency**: rerunning a pass with the same inputs produces the same candidates (modulo timestamps). Re-emitting an existing candidate is a no-op for downstream consumers.
- **Latency target**: `technique_to_finding` < 1 s P95 per tenant after a finding update. `cve_in_inventory` < 60 s P95 per tenant on tenant bootstrap, < 10 s P95 incrementally. `ip/domain/url_in_traffic` is bounded by Sentinel query latency and runs out-of-band.
- **Cost guardrails**: per-tenant daily quota on Sentinel KQL pushdowns and on AI Search vector queries; quotas surface to ops + tenant admin before they hit hard.
- **Explainability**: every candidate carries structured `evidence`. AI engine cites this evidence in any generated narrative; we never paraphrase past it.

---

## 9. Roadmap

- **Phase 2** — light up `correlate_cve_to_inventory`, `correlate_ioc_to_telemetry`, `correlate_technique_to_findings` with KEV + MITRE + Defender TI + Sentinel TI as inputs.
- **Phase 3** — add MISP / OpenCTI / OTX / abuse.ch / GHSA / NVD as inputs; per-source trust calibration.
- **Phase 4** — `correlate_campaign_to_controls` and `correlate_malware_to_posture`; curated malware-family rules pack.
- **Phase 5** — AI engine consumes correlation hits for campaign briefings and copilot answers (with citation enforcement).
- **Phase 6+** — predictive risk modeling: "which control will degrade next, given current campaign drift?"

See `docs/ROADMAP.md`.
