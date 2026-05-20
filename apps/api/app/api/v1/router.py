"""Aggregate v1 router.

Mounts the placeholder + demo-mode domain routers. Real persistence,
auth, and tenant isolation arrive in Phase 1; the demo dashboard /
scores / scans / remediations endpoints are the integration surface for
the frontend until then. See ``docs/DEMO_MODE.md``.
"""

from __future__ import annotations

from fastapi import APIRouter

from app.api.v1 import (
    assets,
    compliance,
    dashboard,
    findings,
    health,
    remediations,
    reports,
    scans,
    scores,
    tenants,
    threat_intel,
)

api_router = APIRouter()

# --- meta -------------------------------------------------------------------
api_router.include_router(health.router, tags=["meta"])

# --- demo-mode composite + canonical read endpoints -------------------------
api_router.include_router(dashboard.router,    prefix="/dashboard",     tags=["dashboard"])
api_router.include_router(scores.router,       prefix="/scores",        tags=["scores"])
api_router.include_router(scans.router,        prefix="/scans",         tags=["scans"])
api_router.include_router(remediations.router, prefix="/remediations",  tags=["remediations"])

# --- domain (placeholders + read-mostly demo) -------------------------------
api_router.include_router(tenants.router,      prefix="/tenants",       tags=["tenants"])
api_router.include_router(assets.router,       prefix="/assets",        tags=["assets"])
api_router.include_router(findings.router,     prefix="/findings",      tags=["findings"])
api_router.include_router(threat_intel.router,                          tags=["threat-intel"])
api_router.include_router(compliance.router,                            tags=["compliance"])
api_router.include_router(reports.router,                               tags=["reports"])

# TODO(phase-1): mount additional domain routers as they come online:
#   - copilot.router       (/copilot)
#   - admin.router         (/admin/...)
#   - webhooks.router      (/webhooks/eventgrid|defender|sentinel)
