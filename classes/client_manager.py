from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urljoin

import requests

from .utils import ask_yes_no


@dataclass
class ClientAddResult:
    success: bool
    status_message: str = ""
    save_path: str | None = None


class ClientManager:
    def __init__(self, podcast, config):
        self.podcast = podcast
        self.config = config
        self.client_config = config.get("client", {})

    def run(self, torrent_path):
        if not self.client_config.get("active", False):
            return None

        resolved_torrent_path = Path(torrent_path) if torrent_path else None
        if not resolved_torrent_path or not resolved_torrent_path.exists():
            raise FileNotFoundError("No torrent file is available for client injection.")

        backend_name = self.client_config.get("backend", "qbittorrent")
        if backend_name != "qbittorrent":
            raise ValueError(f"Unsupported torrent client backend: {backend_name}")

        if self.client_config.get("ask", True):
            if not ask_yes_no(f"Inject {resolved_torrent_path.name} into qBittorrent now", default_yes=True):
                return ClientAddResult(success=False, status_message="Torrent client injection skipped.")

        client = QBittorrentClient(self.podcast, self.client_config)
        return client.add_torrent(resolved_torrent_path)


class QBittorrentClient:
    def __init__(self, podcast, client_config):
        self.podcast = podcast
        self.client_config = client_config
        self.base_url = self._resolve_setting("url", ["QBITTORRENT_URL", "QBT_API_URL"])
        self.username = self._resolve_setting("username", ["QBITTORRENT_USERNAME", "QBT_USER"])
        self.password = self._resolve_setting("password", ["QBITTORRENT_PASSWORD", "QBT_PASS"])
        self.timeout = int(client_config.get("timeout", 30))
        self.category = client_config.get("category")
        self.tags = normalize_tags(client_config.get("tags", []))
        self.paused = bool(client_config.get("paused", False))
        self.skip_checking = bool(client_config.get("skip_checking", False))
        self.session = requests.Session()

    def add_torrent(self, torrent_path):
        self._validate()
        self._login()

        save_path = str(self.podcast.folder_path.parent)
        data = {
            "savepath": save_path,
            "autoTMM": "false",
            "paused": to_qbittorrent_bool(self.paused),
            "skip_checking": to_qbittorrent_bool(self.skip_checking),
            "contentLayout": "Original",
        }
        if self.category:
            data["category"] = str(self.category)
        if self.tags:
            data["tags"] = ",".join(self.tags)

        with Path(torrent_path).open("rb") as handle:
            response = self.session.post(
                self._build_url("api/v2/torrents/add"),
                data=data,
                files={"torrents": (Path(torrent_path).name, handle, "application/x-bittorrent")},
                timeout=self.timeout,
            )

        if response.status_code >= 400:
            raise ValueError(f"qBittorrent rejected the torrent add request: HTTP {response.status_code}")

        response_text = (response.text or "").strip()
        if response_text and response_text != "Ok.":
            raise ValueError(f"qBittorrent rejected the torrent add request: {response_text}")

        return ClientAddResult(
            success=True,
            status_message=f"Injected tracker torrent into qBittorrent using save path {save_path}",
            save_path=save_path,
        )

    def _login(self):
        response = self.session.post(
            self._build_url("api/v2/auth/login"),
            data={"username": self.username, "password": self.password},
            timeout=self.timeout,
        )
        if response.status_code >= 400 or (response.text or "").strip() != "Ok.":
            raise ValueError("Failed to authenticate to qBittorrent. Check the configured client credentials.")

    def _validate(self):
        if not self.base_url:
            raise ValueError("No qBittorrent URL configured. Set client.url or QBITTORRENT_URL/QBT_API_URL.")
        if not self.username or not self.password:
            raise ValueError(
                "No qBittorrent credentials configured. Set client.username/client.password "
                "or QBITTORRENT_USERNAME/QBITTORRENT_PASSWORD."
            )

    def _build_url(self, path):
        return urljoin(f"{self.base_url.rstrip('/')}/", path)

    def _resolve_setting(self, key, env_names):
        value = self.client_config.get(key)
        if value not in (None, ""):
            return value
        for env_name in env_names:
            env_value = os.getenv(env_name)
            if env_value not in (None, ""):
                return env_value
        return None


def normalize_tags(tags):
    if isinstance(tags, str):
        tags = [part.strip() for part in tags.split(",")]
    return [str(tag).strip() for tag in (tags or []) if str(tag).strip()]


def to_qbittorrent_bool(value):
    return "true" if value else "false"
