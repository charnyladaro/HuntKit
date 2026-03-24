import json
import os
from datetime import datetime
from pathlib import Path
from typing import Any


RESULTS_DIR = Path("results")


def get_target_dir(target: str) -> Path:
    safe = target.replace("https://", "").replace("http://", "").replace("/", "_").strip("_")
    d = RESULTS_DIR / safe
    d.mkdir(parents=True, exist_ok=True)
    return d


def save_phase(target: str, phase: str, data: Any):
    """Persist phase results as JSON."""
    d = get_target_dir(target)
    fp = d / f"{phase}.json"
    payload = {
        "phase": phase,
        "target": target,
        "timestamp": datetime.now().isoformat(),
        "data": data,
    }
    with open(fp, "w") as f:
        json.dump(payload, f, indent=2)


def load_phase(target: str, phase: str) -> Any:
    """Load previously saved phase results."""
    fp = get_target_dir(target) / f"{phase}.json"
    if not fp.exists():
        return None
    with open(fp) as f:
        payload = json.load(f)
    return payload.get("data")


def phase_done(target: str, phase: str) -> bool:
    return (get_target_dir(target) / f"{phase}.json").exists()


def save_raw(target: str, filename: str, content: str):
    """Save raw text output (e.g., tool stdout)."""
    d = get_target_dir(target)
    with open(d / filename, "w") as f:
        f.write(content)


def load_all_phases(target: str) -> dict:
    """Load all completed phase results for report generation."""
    phases = ["recon", "discovery", "scanning", "manual", "report_meta"]
    result = {}
    for phase in phases:
        data = load_phase(target, phase)
        if data is not None:
            result[phase] = data
    return result


def list_targets() -> list[str]:
    if not RESULTS_DIR.exists():
        return []
    return [d.name for d in RESULTS_DIR.iterdir() if d.is_dir()]
