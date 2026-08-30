"""Load versioned predicate definitions and resolve category -> predicate.

Predicates live in data/predicates/<os_major>.json so that adding support for a
new macOS version is a data change, not a code change (spec section 8).
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

_DATA_DIR = Path(__file__).parent / "data" / "predicates"

CATEGORIES = (
    "mdm_command",
    "enrollment",
    "push",
    "scheduling",
    "asset_download",
    "ddm",
    "declaration",
    "pkg_install",
    "profile_payload",
)


class PredicateError(ValueError):
    pass


def _available_versions() -> list[int]:
    return sorted(int(p.stem) for p in _DATA_DIR.glob("*.json") if p.stem.isdigit())


def load(os_major: int) -> dict:
    """Load the predicate table for an OS major version.

    Falls back to the highest available version <= requested, so an unknown
    newer build still resolves (with a caveat the caller can surface).
    """
    versions = _available_versions()
    if not versions:
        raise PredicateError("no predicate definition files found")
    chosen = None
    for v in versions:
        if v <= os_major:
            chosen = v
    if chosen is None:
        chosen = versions[0]
    data = json.loads((_DATA_DIR / f"{chosen}.json").read_text())
    data["_resolved_version"] = chosen
    data["_requested_version"] = os_major
    data["_exact"] = chosen == os_major
    return data


def resolve(category: str, os_major: int) -> dict:
    """Return {predicate, level, confidence, exact, ...} for a category."""
    if category not in CATEGORIES:
        raise PredicateError(
            f"unknown category {category!r}; valid: {', '.join(CATEGORIES)}"
        )
    table = load(os_major)
    entry = table["categories"][category]
    return {
        "category": category,
        "predicate": entry["predicate"],
        "level": entry.get("level", "info"),
        "confidence": entry.get("confidence", "medium"),
        "note": entry.get("note"),
        "predicate_version": table["_resolved_version"],
        "exact_version_match": table["_exact"],
    }
