# profiles_loader.py
"""
Load YAML threat/crypto profiles and provide deterministic profile hashing.
"""
from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from typing import Dict, Any

import yaml


@dataclass(frozen=True)
class Profile:
    profile_id: str
    raw: Dict[str, Any]
    policy_hash: str


def _canonical_json(obj: Dict[str, Any]) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def load_profiles(profiles_dir: str) -> Dict[str, Profile]:
    profiles: Dict[str, Profile] = {}
    if not os.path.isdir(profiles_dir):
        raise FileNotFoundError(f"profiles directory not found: {profiles_dir}")

    for name in sorted(os.listdir(profiles_dir)):
        if not name.endswith((".yaml", ".yml")):
            continue
        path = os.path.join(profiles_dir, name)
        with open(path, "r", encoding="utf-8") as f:
            raw = yaml.safe_load(f) or {}
        profile_id = str(raw.get("profile_id") or os.path.splitext(name)[0])
        policy_hash = hashlib.sha256(_canonical_json(raw).encode("utf-8")).hexdigest()
        profiles[profile_id] = Profile(profile_id=profile_id, raw=raw, policy_hash=policy_hash)

    if not profiles:
        raise ValueError("no profiles loaded")
    return profiles
