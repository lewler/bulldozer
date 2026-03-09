from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse


def get_split_state_path(staging_root, display_name):
    return Path(staging_root) / f".{display_name}.bulldozer-split-state.json"


def load_split_state(state_path):
    path = Path(state_path)
    if not path.exists():
        return None

    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None


def save_split_state(state_path, state):
    path = Path(state_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(state, indent=2, sort_keys=True), encoding="utf-8")


def initialize_split_state(state_path, source_path, split_mode, split_folder_paths):
    existing_state = load_split_state(state_path) or {}
    state = {
        "version": 1,
        "source_path": str(Path(source_path)),
        "split_mode": split_mode,
        "split_folders": [Path(folder_path).name for folder_path in split_folder_paths],
        "completed_folders": existing_state.get("completed_folders", {}),
        "last_prompt_defaults": existing_state.get("last_prompt_defaults", {}),
    }
    save_split_state(state_path, state)
    return state


def get_remaining_split_paths(state_path, state=None):
    state = state or load_split_state(state_path) or {}
    root = Path(state_path).parent
    completed_folders = set((state.get("completed_folders") or {}).keys())
    remaining_paths = []
    for folder_name in state.get("split_folders", []):
        if folder_name in completed_folders:
            continue
        folder_path = root / folder_name
        if folder_path.exists():
            remaining_paths.append(folder_path)
    return remaining_paths


def get_split_folder_paths(state_path, state=None):
    state = state or load_split_state(state_path) or {}
    root = Path(state_path).parent
    existing_paths = []
    missing_paths = []
    for folder_name in state.get("split_folders", []):
        folder_path = root / folder_name
        if folder_path.exists():
            existing_paths.append(folder_path)
        else:
            missing_paths.append(folder_path)
    return existing_paths, missing_paths


def bind_runtime_split_state(config, state_path, state=None):
    runtime = config.setdefault("_runtime", {})
    state = state or load_split_state(state_path) or {}
    runtime["split_state"] = {
        "path": str(Path(state_path)),
        "data": state,
    }
    if state.get("last_prompt_defaults"):
        runtime["upload_prompt_defaults"] = dict(state["last_prompt_defaults"])
    return state


def enable_split_auto_apply(config, redo_plan=None):
    runtime = config.setdefault("_runtime", {})
    runtime["split_auto_apply_remaining"] = True
    runtime["split_auto_apply_redo_plan"] = dict(redo_plan or {})
    return runtime["split_auto_apply_redo_plan"]


def disable_split_auto_apply(config):
    runtime = config.setdefault("_runtime", {})
    runtime["split_auto_apply_remaining"] = False
    runtime["split_auto_apply_redo_plan"] = {}


def is_split_auto_apply_active(config):
    return bool((config.get("_runtime") or {}).get("split_auto_apply_remaining", False))


def get_split_auto_apply_redo_plan(config):
    return dict((config.get("_runtime") or {}).get("split_auto_apply_redo_plan") or {})


def get_split_folder_record(config, folder_path):
    runtime = config.get("_runtime", {})
    split_state_runtime = runtime.get("split_state") or {}
    state = split_state_runtime.get("data") or {}
    completed_folders = state.get("completed_folders") or {}
    return completed_folders.get(Path(folder_path).name)


def backfill_completed_folders(config, state_path, state=None):
    state = state or load_split_state(state_path) or {}
    completed_folders = state.setdefault("completed_folders", {})
    changed = False

    for folder_name in state.get("split_folders", []):
        if folder_name in completed_folders:
            continue
        tracker_torrent_path = find_existing_tracker_torrent(config, state_path, folder_name)
        if not tracker_torrent_path:
            continue
        completed_folders[folder_name] = {
            "processed_at": None,
            "completed_at": None,
            "details_url": None,
            "download_url": None,
            "tracker_torrent_path": str(tracker_torrent_path),
            "discovered_from_artifacts": True,
        }
        changed = True

    if changed:
        save_split_state(state_path, state)
    return state


def remember_upload_prompt_defaults(
    config,
    *,
    category_id,
    type_id,
    anonymous,
    personal_release,
    ads_removed,
    extra_keywords,
):
    defaults = {
        "category_id": str(category_id),
        "type_id": str(type_id),
        "anonymous": bool(anonymous),
        "personal_release": bool(personal_release),
        "ads_removed": bool(ads_removed),
        "extra_keywords": list(extra_keywords or []),
    }
    runtime = config.setdefault("_runtime", {})
    runtime["upload_prompt_defaults"] = defaults

    split_state_runtime = runtime.get("split_state") or {}
    state_path = split_state_runtime.get("path")
    if not state_path:
        return defaults

    state = split_state_runtime.get("data") or load_split_state(state_path) or {}
    state["last_prompt_defaults"] = defaults
    save_split_state(state_path, state)
    split_state_runtime["data"] = state
    return defaults


def mark_split_folder_processed(config, folder_path):
    runtime = config.get("_runtime", {})
    split_state_runtime = runtime.get("split_state") or {}
    state_path = split_state_runtime.get("path")
    if not state_path:
        return None

    state = split_state_runtime.get("data") or load_split_state(state_path) or {}
    completed_folders = state.setdefault("completed_folders", {})
    folder_name = Path(folder_path).name
    record = completed_folders.setdefault(folder_name, {})
    record["processed_at"] = datetime.now(timezone.utc).isoformat()
    save_split_state(state_path, state)
    split_state_runtime["data"] = state
    return record


def mark_split_folder_completed(config, folder_path, result=None):
    runtime = config.get("_runtime", {})
    split_state_runtime = runtime.get("split_state") or {}
    state_path = split_state_runtime.get("path")
    if not state_path:
        return None

    state = split_state_runtime.get("data") or load_split_state(state_path) or {}
    completed_folders = state.setdefault("completed_folders", {})
    folder_name = Path(folder_path).name
    prior_record = completed_folders.get(folder_name, {})
    completed_folders[folder_name] = {
        "processed_at": prior_record.get("processed_at"),
        "completed_at": datetime.now(timezone.utc).isoformat(),
        "details_url": getattr(result, "details_url", None),
        "download_url": getattr(result, "download_url", None),
        "tracker_torrent_path": str(getattr(result, "tracker_torrent_path", "") or ""),
    }
    save_split_state(state_path, state)
    split_state_runtime["data"] = state
    return completed_folders[folder_name]


def mark_split_folder_client_injected(config, folder_path, client_result=None):
    runtime = config.get("_runtime", {})
    split_state_runtime = runtime.get("split_state") or {}
    state_path = split_state_runtime.get("path")
    if not state_path:
        return None

    state = split_state_runtime.get("data") or load_split_state(state_path) or {}
    completed_folders = state.setdefault("completed_folders", {})
    folder_name = Path(folder_path).name
    record = completed_folders.setdefault(folder_name, {})
    record["client_injected_at"] = datetime.now(timezone.utc).isoformat()
    record["client_present"] = True
    if client_result is not None:
        save_path = getattr(client_result, "save_path", None)
        infohash = getattr(client_result, "infohash", None)
        if save_path:
            record["client_save_path"] = str(save_path)
        if infohash:
            record["client_infohash"] = str(infohash)
    save_split_state(state_path, state)
    split_state_runtime["data"] = state
    return record


def find_existing_tracker_torrent(config, state_path, folder_name):
    upload_host = (
        urlparse(str(config.get("upload", {}).get("base_url", ""))).netloc.replace(":", "_")
        if config.get("upload", {}).get("base_url")
        else None
    )
    filenames = [f"{folder_name}.tracker.torrent"]
    if upload_host:
        filenames.insert(0, f"{folder_name}.{upload_host}.tracker.torrent")

    for root in _build_artifact_search_roots(config, state_path):
        if not root.exists() or not root.is_dir():
            continue
        found = _find_tracker_torrent_under_root(root, filenames, max_depth=3)
        if found:
            return found
    return None


def find_existing_local_torrent(config, state_path, folder_name):
    filenames = [f"{folder_name}.torrent"]
    for root in _build_artifact_search_roots(config, state_path):
        if not root.exists() or not root.is_dir():
            continue
        found = _find_tracker_torrent_under_root(root, filenames, max_depth=3)
        if found:
            return found
    return None


def _build_artifact_search_roots(config, state_path):
    state_root = Path(state_path).parent
    candidate_roots = [state_root]

    for configured_path in (
        config.get("staging", {}).get("path"),
        config.get("client", {}).get("save_path"),
    ):
        if not configured_path:
            continue
        candidate_roots.append(Path(configured_path).expanduser())

    expanded_roots = []
    seen_roots = set()
    for root in candidate_roots:
        try:
            resolved = root.resolve()
        except OSError:
            resolved = Path(root)
        for candidate in (resolved, resolved.parent):
            marker = str(candidate)
            if marker in seen_roots:
                continue
            seen_roots.add(marker)
            expanded_roots.append(candidate)
    return expanded_roots


def _find_tracker_torrent_under_root(root, filenames, max_depth):
    root = Path(root)
    base_depth = len(root.parts)
    lowered_filenames = {filename.casefold() for filename in filenames}

    for current_root, dirnames, filenames_in_dir in os.walk(root):
        current_path = Path(current_root)
        depth = len(current_path.parts) - base_depth
        if depth > max_depth:
            dirnames[:] = []
            continue

        for filename in filenames_in_dir:
            if filename.casefold() in lowered_filenames:
                return current_path / filename
    return None
