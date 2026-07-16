"""Engagement playbook chains: ordered presets run as sequential scan jobs.

Does not auto-execute planner commands. Only queues authorized scan profiles
(discovery → map → safe by default) through the existing job path.
"""

from __future__ import annotations

import uuid
from typing import Any, Dict, List, Optional, Sequence, Tuple

from recon_operator.presets import PHASE_ORDER, get_preset

DEFAULT_PLAYBOOK_ID = "standard"
PLAYBOOKS: Dict[str, Dict[str, Any]] = {
    "standard": {
        "id": "standard",
        "label": "Standard recon chain",
        "description": "discovery → map → safe (authorized recon only)",
        "phases": list(PHASE_ORDER),
    },
    "quick": {
        "id": "quick",
        "label": "Quick map",
        "description": "discovery → map",
        "phases": ["discovery", "map"],
    },
    "deep": {
        "id": "deep",
        "label": "Deep authorized chain",
        "description": "discovery → map → safe → depth",
        "phases": ["discovery", "map", "safe", "depth"],
    },
}


def list_playbooks() -> List[Dict[str, Any]]:
    rows = [dict(value) for value in PLAYBOOKS.values()]
    rows.sort(key=lambda item: item.get("id") or "")
    return rows


def resolve_phases(
    *,
    playbook: Optional[str] = None,
    phases: Optional[Sequence[str]] = None,
) -> Tuple[Optional[List[str]], Optional[str], Optional[str]]:
    """Return (phase_ids, playbook_id, error)."""
    if phases is not None:
        if not isinstance(phases, (list, tuple)) or not phases:
            return None, None, "phases must be a non-empty list of preset ids"
        resolved: List[str] = []
        for raw in phases:
            key = str(raw or "").strip().lower()
            if not key:
                return None, None, "phases contains an empty id"
            if get_preset(key) is None:
                return None, None, f"Unknown phase/preset {raw!r}"
            resolved.append(key)
        return resolved, "custom", None

    playbook_id = str(playbook or DEFAULT_PLAYBOOK_ID).strip().lower() or DEFAULT_PLAYBOOK_ID
    pb = PLAYBOOKS.get(playbook_id)
    if pb is None:
        known = ", ".join(sorted(PLAYBOOKS.keys()))
        return None, None, f"Unknown playbook {playbook_id!r}. Known: {known}"
    return list(pb["phases"]), playbook_id, None


def build_engagement_record(
    *,
    target: str,
    phase_ids: Sequence[str],
    playbook_id: str,
    owner_id: str,
) -> Dict[str, Any]:
    engagement_id = str(uuid.uuid4())
    steps = []
    for index, phase_id in enumerate(phase_ids):
        preset = get_preset(phase_id) or {}
        steps.append(
            {
                "index": index,
                "phase": phase_id,
                "preset_phase": preset.get("phase"),
                "scan_type": preset.get("scan_type"),
                "ports": preset.get("ports"),
                "scripts": preset.get("scripts"),
                "discovery": preset.get("discovery"),
                "status": "pending",
                "job_id": None,
                "error": None,
                "result_file": None,
            }
        )
    return {
        "engagement_id": engagement_id,
        "playbook": playbook_id,
        "target": target,
        "owner_id": owner_id,
        "status": "queued",
        "current_index": 0,
        "steps": steps,
    }


def public_engagement_view(record: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "engagement_id": record.get("engagement_id"),
        "playbook": record.get("playbook"),
        "target": record.get("target"),
        "status": record.get("status"),
        "current_index": record.get("current_index"),
        "steps": [
            {
                "index": step.get("index"),
                "phase": step.get("phase"),
                "preset_phase": step.get("preset_phase"),
                "scan_type": step.get("scan_type"),
                "ports": step.get("ports"),
                "status": step.get("status"),
                "job_id": step.get("job_id"),
                "error": step.get("error"),
                "result_file": step.get("result_file"),
            }
            for step in (record.get("steps") or [])
            if isinstance(step, dict)
        ],
    }
