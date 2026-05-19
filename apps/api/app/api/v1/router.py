"""Aggregate v1 router.

Mounts the placeholder domain routers. Real persistence, auth, and tenant
isolation arrive in Phase 1; the routers here return deterministic mock
responses so the frontend and external contract consumers (see
``packages/contracts/``) can integrate against a stable shape.
"""

from __future__ import annotations

from fastapi import APIRouter

from app.api.v1 import (
    assets,
    compliance,
    findings,
    health,
    reports,
    tenants,
    threat_intel,
)

api_router = APIRouter()

# --- meta -------------------------------------------------------------------
api_router.include_router(health.router, tags=["meta"])

# --- domain (placeholders) --------------------------------------------------
api_router.include_router(tenants.router,     prefix="/tenants",  tags=["tenants"])
api_router.include_router(assets.router,      prefix="/assets",   tags=["assets"])
api_router.include_router(findings.router,    prefix="/findings", tags=["findings"])
api_router.include_router(threat_intel.router,                    tags=["threat-intel"])
api_router.include_router(compliance.router,                      tags=["compliance"])
api_router.include_router(reports.router,                         tags=["reports"])

# TODO(phase-1): mount additional domain routers as they come online:
#   - scores.router        (/scores)
#   - scans.router         (/scans)
#   - copilot.router       (/copilot)
#   - admin.router         (/admin/...)
#   - webhooks.router      (/webhooks/eventgrid|defender|sentinel)
