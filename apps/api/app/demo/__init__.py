"""Demo-mode data + service layer.

Phase 7 makes the API usable end-to-end against an in-process, deterministic
dataset for a fictional tenant ("Contoso Demo"). NO database, NO Microsoft
calls, NO external feeds. Every read is served from immutable Python
constants in ``data.py`` via the singleton service in ``service.py``.

This package exists so the frontend, partner integrators, and contract
test suites can integrate against stable shapes today, and so the same
endpoints can be flipped to real persistence in Phase 1 without changing
the wire contract. See ``docs/DEMO_MODE.md``.
"""

from app.demo.service import DemoService, demo_service

__all__ = ["DemoService", "demo_service"]
