from __future__ import annotations

import os
import shutil
from pathlib import Path

from .utils import announce, ask_yes_no, log


class StagingManager:
    def __init__(self, config):
        self.config = config
        self.staging_config = config.get("staging", {})

    def prepare(self, folder_path, display_name=None, force=False):
        source_path = Path(folder_path).expanduser().resolve()
        should_stage = force or self.staging_config.get("active", False)
        if not should_stage:
            self._store_runtime(False, None, source_path, source_path)
            return source_path

        staging_root = self._resolve_staging_root(source_path)
        if source_path == staging_root or staging_root in source_path.parents:
            log(f"Skipping staging because {source_path} is already inside {staging_root}", "info")
            self._store_runtime(False, None, source_path, source_path)
            return source_path

        stage_name = display_name or source_path.name
        target_path = staging_root / stage_name
        if source_path == target_path:
            self._store_runtime(False, None, source_path, source_path)
            return source_path

        if self.staging_config.get("ask", False):
            if not ask_yes_no(f"Stage {source_path} into {target_path} before processing"):
                self._store_runtime(False, None, source_path, source_path)
                return source_path

        overwrite = self.staging_config.get("overwrite", True)
        if target_path.exists():
            if overwrite:
                self._remove_existing_target(target_path)
            else:
                raise FileExistsError(
                    f"Staging target already exists: {target_path}. "
                    "Remove it or enable staging.overwrite."
                )

        mode = str(self.staging_config.get("mode", "hardlink")).lower()
        if mode not in {"hardlink", "copy"}:
            raise ValueError(f"Unsupported staging mode: {mode}")

        target_path.mkdir(parents=True, exist_ok=True)
        self._populate_tree(source_path, target_path, mode)

        protect_source_content = bool(self.staging_config.get("protect_source_content", True))
        self._store_runtime(True, mode, source_path, target_path, protect_source_content=protect_source_content)
        announce(f"Staged local folder to {target_path} using {mode} mode", "info")
        return target_path

    def _resolve_staging_root(self, source_path):
        configured_path = self.staging_config.get("path")
        if configured_path:
            staging_root = Path(configured_path).expanduser()
            if not staging_root.is_absolute():
                staging_root = Path.cwd() / staging_root
        else:
            staging_root = source_path.parent / ".bulldozer-staging"
        staging_root.mkdir(parents=True, exist_ok=True)
        return staging_root.resolve()

    def _remove_existing_target(self, target_path):
        if target_path.is_dir() and not target_path.is_symlink():
            shutil.rmtree(target_path)
            return
        target_path.unlink()

    def _populate_tree(self, source_path, target_path, mode):
        for root, dirnames, filenames in os.walk(source_path):
            current_source = Path(root)
            relative_root = current_source.relative_to(source_path)
            current_target = target_path / relative_root
            current_target.mkdir(parents=True, exist_ok=True)

            for dirname in dirnames:
                (current_target / dirname).mkdir(parents=True, exist_ok=True)

            for filename in filenames:
                source_file = current_source / filename
                target_file = current_target / filename
                if mode == "hardlink":
                    os.link(source_file, target_file)
                else:
                    shutil.copy2(source_file, target_file)

    def _store_runtime(self, active, mode, source_path, staged_path, protect_source_content=False):
        self.config["_staging_runtime"] = {
            "active": bool(active),
            "mode": mode,
            "source_path": str(source_path),
            "staged_path": str(staged_path),
            "protect_source_content": bool(protect_source_content),
        }
