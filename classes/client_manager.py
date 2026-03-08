from __future__ import annotations

import hashlib
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
    infohash: str | None = None


@dataclass
class ClientInspectResult:
    present: bool
    infohash: str | None = None
    save_path: str | None = None
    status_message: str = ""


class ClientManager:
    def __init__(self, podcast, config):
        self.podcast = podcast
        self.config = config
        self.client_config = config.get("client", {})

    def run(self, torrent_path, prompt_default_yes=True):
        if not self.client_config.get("active", False):
            return None

        resolved_torrent_path = Path(torrent_path) if torrent_path else None
        if not resolved_torrent_path or not resolved_torrent_path.exists():
            raise FileNotFoundError("No torrent file is available for client injection.")

        backend_name = self.client_config.get("backend", "qbittorrent")
        if backend_name != "qbittorrent":
            raise ValueError(f"Unsupported torrent client backend: {backend_name}")

        if self.client_config.get("ask", True):
            if not ask_yes_no(
                f"Inject {resolved_torrent_path.name} into qBittorrent now",
                default_yes=prompt_default_yes,
            ):
                return ClientAddResult(success=False, status_message="Torrent client injection skipped.")

        client = QBittorrentClient(self.podcast, self.client_config)
        return client.add_torrent(resolved_torrent_path)

    def inspect(self, torrent_path):
        if not self.client_config.get("active", False):
            return None

        resolved_torrent_path = Path(torrent_path) if torrent_path else None
        if not resolved_torrent_path or not resolved_torrent_path.exists():
            return None

        backend_name = self.client_config.get("backend", "qbittorrent")
        if backend_name != "qbittorrent":
            raise ValueError(f"Unsupported torrent client backend: {backend_name}")

        client = QBittorrentClient(self.podcast, self.client_config)
        return client.inspect_torrent(resolved_torrent_path)


class QBittorrentClient:
    def __init__(self, podcast, client_config):
        self.podcast = podcast
        self.client_config = client_config
        self.base_url = self._resolve_setting("url", ["QBITTORRENT_URL", "QBT_API_URL"])
        self.username = self._resolve_setting("username", ["QBITTORRENT_USERNAME", "QBT_USER"])
        self.password = self._resolve_setting("password", ["QBITTORRENT_PASSWORD", "QBT_PASS"])
        self.save_path = self._resolve_setting("save_path", ["QBITTORRENT_SAVE_PATH", "QBT_SAVE_PATH"])
        self.timeout = int(client_config.get("timeout", 30))
        self.category = client_config.get("category")
        self.tags = normalize_tags(client_config.get("tags", []))
        self.paused = bool(client_config.get("paused", False))
        self.skip_checking = bool(client_config.get("skip_checking", False))
        self.session = requests.Session()

    def add_torrent(self, torrent_path):
        self._validate()
        self._login()
        infohash = compute_v1_torrent_infohash(Path(torrent_path))

        save_path = self._determine_save_path()
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
            existing = self._inspect_existing_infohash(infohash)
            if existing:
                existing_save_path = existing.get("save_path")
                if existing_save_path:
                    status_message = (
                        f"Tracker torrent is already present in qBittorrent with save path {existing_save_path}; "
                        "leaving the existing entry in place"
                    )
                else:
                    status_message = (
                        f"Tracker torrent is already present in qBittorrent with infohash {infohash}; "
                        "leaving the existing entry in place"
                    )
                return ClientAddResult(
                    success=True,
                    status_message=status_message,
                    save_path=existing_save_path or save_path,
                    infohash=infohash,
                )
            raise ValueError(f"qBittorrent rejected the torrent add request: {response_text}")

        return ClientAddResult(
            success=True,
            status_message=f"Injected tracker torrent into qBittorrent using save path {save_path}",
            save_path=save_path,
            infohash=infohash,
        )

    def inspect_torrent(self, torrent_path):
        self._validate()
        self._login()
        infohash = compute_v1_torrent_infohash(Path(torrent_path))
        items = self._get_torrent_info(infohash)
        if items:
            save_path = items[0].get("save_path")
            return ClientInspectResult(
                present=True,
                infohash=infohash,
                save_path=save_path,
                status_message=f"Torrent already exists in qBittorrent with infohash {infohash}",
            )
        return ClientInspectResult(
            present=False,
            infohash=infohash,
            status_message=f"Torrent is not present in qBittorrent for infohash {infohash}",
        )

    def _inspect_existing_infohash(self, infohash):
        items = self._get_torrent_info(infohash)
        if items:
            return items[0]
        return None

    def _get_torrent_info(self, infohash):
        response = self.session.get(
            self._build_url("api/v2/torrents/info"),
            params={"hashes": infohash},
            timeout=self.timeout,
        )
        if response.status_code >= 400:
            raise ValueError(f"qBittorrent torrent inspection failed: HTTP {response.status_code}")
        return response.json() if response.text else []

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

    def _determine_save_path(self):
        if self.save_path:
            candidate = Path(self.save_path).expanduser()
            if not candidate.is_absolute():
                candidate = (self.podcast.folder_path.parent / candidate).resolve()
            return str(candidate)
        return str(self.podcast.folder_path.parent)

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


def compute_v1_torrent_infohash(torrent_path):
    data = Path(torrent_path).read_bytes()
    if not data.startswith(b"d"):
        raise ValueError(f"Torrent file is not bencoded: {torrent_path}")

    index = 1
    while index < len(data) and data[index:index + 1] != b"e":
        key, index = _parse_bencoded_bytes(data, index)
        value_start = index
        index = _skip_bencoded_value(data, index)
        if key == b"info":
            return hashlib.sha1(data[value_start:index]).hexdigest()

    raise ValueError(f"Torrent file {torrent_path} does not contain an info dictionary")


def _parse_bencoded_bytes(data, index):
    colon_index = data.index(b":", index)
    length = int(data[index:colon_index])
    value_start = colon_index + 1
    value_end = value_start + length
    return data[value_start:value_end], value_end


def _skip_bencoded_value(data, index):
    marker = data[index:index + 1]
    if marker == b"i":
        return data.index(b"e", index) + 1
    if marker == b"l" or marker == b"d":
        index += 1
        if marker == b"d":
            while data[index:index + 1] != b"e":
                _, index = _parse_bencoded_bytes(data, index)
                index = _skip_bencoded_value(data, index)
            return index + 1
        while data[index:index + 1] != b"e":
            index = _skip_bencoded_value(data, index)
        return index + 1
    if marker.isdigit():
        _, end_index = _parse_bencoded_bytes(data, index)
        return end_index
    raise ValueError("Invalid bencoded value")
