"""Aggregate v1 router.

Each domain (findings, scores, frameworks, threats, scans, reports, copilot,
admin) will have its own module under app/api/v1/ and be included here.
Skeleton mounts only the health router.
"""

from __future__ import annotations

from fastapi import APIRouter

from app.api.v1.health import router as health_router

api_router = APIRouter()
api_router.include_router(health_router, tags=["meta"])

# TODO(phase-1): mount additional domain routers.
# from app.api.v1 import findings, scores, frameworks, threats, scans, reports, copilot, admin
# api_router.include_router(findings.router,    prefix="/findings",    tags=["findings"])
# api_router.include_router(scores.router,      prefix="/scores",      tags=["scores"])
# api_router.include_router(frameworks.router,  prefix="/frameworks",  tags=["frameworks"])
# api_router.include_router(threats.router,     prefix="/threats",     tags=["threats"])
# api_router.include_router(scans.router,       prefix="/scans",       tags=["scans"])
# api_router.include_router(reports.router,     prefix="/reports",     tags=["reports"])
# api_router.include_router(copilot.router,     prefix="/copilot",     tags=["copilot"])
# api_router.include_router(admin.router,       prefix="/admin",       tags=["admin"])
