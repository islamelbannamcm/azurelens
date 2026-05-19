"""AzureLens Threat Intelligence engine.

Logical subpackages (added in later phases):
  - threat_intel.ingest      : per-source connectors (Defender TI, Sentinel TI,
                                CISA KEV, MITRE, MISP, OpenCTI, OTX, abuse.ch,
                                VirusTotal, GHSA, NVD)
  - threat_intel.normalize   : STIX 2.1 alignment + dedupe + enrichment
  - threat_intel.correlate   : TI graph ⨝ tenant asset graph
"""
