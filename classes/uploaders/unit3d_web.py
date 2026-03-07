from __future__ import annotations

import base64
import http.cookiejar
import json
import re
import tempfile
from dataclasses import dataclass, field
from fnmatch import fnmatch
from pathlib import Path
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup
from PIL import Image, ImageFilter, ImageOps

from ..upload_context import ReleaseProfile, UploadContextBuilder
from ..utils import ask_yes_no, ask_yes_no_default, choose_option, take_input


MAX_UPLOAD_BYTES = 950_000
UPLOAD_SAFETY_MARGIN_BYTES = 25_000
DEFAULT_COVER_SIZE = (600, 600)
DEFAULT_BANNER_SIZE = (1280, 720)
MIN_BANNER_SIZE = (960, 540)
DEFAULT_IMAGE_QUALITY = 88
MIN_IMAGE_QUALITY = 46
QUALITY_STEP = 6

try:
    RESAMPLING_LANCZOS = Image.Resampling.LANCZOS
except AttributeError:
    RESAMPLING_LANCZOS = Image.LANCZOS


@dataclass
class UploadPreparation:
    payload: dict
    warnings: list[str]
    category_name: str
    type_name: str
    csrf_token: str
    upload_url: str
    torrent_path: Path
    cover_path: Path | None = None
    banner_path: Path | None = None
    nfo_path: Path | None = None
    release_profile: ReleaseProfile | None = None


@dataclass
class UploadResult:
    success: bool
    details_url: str | None = None
    download_url: str | None = None
    validation_errors: list[str] = field(default_factory=list)
    status_message: str = ""
    tracker_torrent_path: Path | None = None


class Unit3DWebUploader:
    def __init__(self, podcast, config, upload_context, torrent_path):
        self.podcast = podcast
        self.config = config
        self.upload_context = upload_context
        self.upload_config = config.get("upload", {})
        self.base_url = self.upload_config.get("base_url", "").rstrip("/")
        self.upload_page_urls = self._build_upload_page_urls()
        self.torrent_path = Path(torrent_path)
        self.timeout = self.upload_config.get("timeout", 60)
        self.user_agent = self.upload_config.get("user_agent", "Bulldozer uploader")
        self.require_images = self.upload_config.get("require_images", True)
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": self.user_agent})
        self._temp_dir = tempfile.TemporaryDirectory(prefix="bulldozer-upload-")
        self.temp_dir = Path(self._temp_dir.name)
        self.release_profile = None
        self._asset_warnings = []
        self._cover_source_path = None

    def cleanup(self):
        self._temp_dir.cleanup()

    def run_preflight(self, dry_run=False):
        self._asset_warnings = []
        self._load_session_cookies()
        response, submit_url = self._load_upload_form_page()

        html = response.text
        csrf_token = extract_csrf_token(html)
        if not csrf_token:
            raise ValueError("Could not extract a CSRF token from the UNIT3D upload page.")
        form_defaults = extract_form_defaults(html)
        category_metadata = parse_category_metadata(html)

        category_options = parse_select_options(html, "category_id")
        type_options = parse_select_options(html, "type_id")
        self.release_profile = self._resolve_release_profile(
            category_options,
            type_options,
            category_metadata,
            dry_run=dry_run,
        )
        self.upload_context = UploadContextBuilder(self.podcast, self.config).build(release_profile=self.release_profile)

        nfo_path = self._discover_nfo_path()
        cover_path = self._prepare_cover_image()
        banner_path = self._prepare_banner_image(nfo_path=nfo_path, cover_path=cover_path, dry_run=dry_run)
        payload = self._build_payload(csrf_token=csrf_token, form_defaults=form_defaults)

        if len(payload["name"]) > 255:
            raise ValueError("Upload title exceeds UNIT3D's 255 character limit.")
        if len(payload["description"]) > 65_535:
            raise ValueError("Rendered description exceeds UNIT3D's 65535 character limit.")

        warnings = list(self.upload_context.warnings)
        warnings.extend(self._asset_warnings)
        warnings.extend(self._build_size_warnings(nfo_path=nfo_path, cover_path=cover_path, banner_path=banner_path))

        return UploadPreparation(
            payload=payload,
            warnings=warnings,
            category_name=self.release_profile.category_name,
            type_name=self.release_profile.type_name,
            csrf_token=csrf_token,
            upload_url=submit_url,
            torrent_path=self.torrent_path,
            cover_path=cover_path,
            banner_path=banner_path,
            nfo_path=nfo_path,
            release_profile=self.release_profile,
        )

    def submit(self, preparation):
        files = {}
        handles = []
        try:
            handles.append(preparation.torrent_path.open("rb"))
            files["torrent"] = (
                preparation.torrent_path.name,
                handles[-1],
                "application/x-bittorrent",
            )

            if preparation.nfo_path:
                handles.append(preparation.nfo_path.open("rb"))
                files["nfo"] = (preparation.nfo_path.name, handles[-1], "text/plain")

            if preparation.cover_path:
                handles.append(preparation.cover_path.open("rb"))
                files["torrent-cover"] = (preparation.cover_path.name, handles[-1], "image/jpeg")

            if preparation.banner_path:
                handles.append(preparation.banner_path.open("rb"))
                files["torrent-banner"] = (preparation.banner_path.name, handles[-1], "image/jpeg")

            response = self.session.post(
                preparation.upload_url,
                data=preparation.payload,
                files=files,
                timeout=self.timeout,
                allow_redirects=True,
            )
        finally:
            for handle in handles:
                handle.close()

        if self._looks_like_login_page(response.url, response.text):
            return UploadResult(success=False, status_message="Upload failed because the session appears to be expired.")

        details_url, download_url = extract_success_links(self.base_url, str(response.url), response.text)
        if details_url and download_url:
            tracker_torrent_path = None
            if self.upload_config.get("download_uploaded_torrent", True):
                tracker_torrent_path = self._download_uploaded_torrent(download_url)
            return UploadResult(
                success=True,
                details_url=details_url,
                download_url=download_url,
                status_message=f"Upload completed successfully: {details_url}",
                tracker_torrent_path=tracker_torrent_path,
            )

        validation_errors = extract_validation_errors(response.text)
        if validation_errors:
            return UploadResult(
                success=False,
                validation_errors=validation_errors,
                status_message="Tracker returned validation errors.",
            )

        if response.status_code >= 400:
            return UploadResult(
                success=False,
                status_message=f"Upload failed with HTTP {response.status_code}.",
            )

        return UploadResult(
            success=False,
            status_message="Upload did not reach a download-check page. Review the tracker response manually.",
        )

    def _load_session_cookies(self):
        cookie_file = Path(self.upload_config.get("cookie_file", "")).expanduser()
        if not cookie_file.is_absolute():
            cookie_file = Path.cwd() / cookie_file
        if not cookie_file.exists():
            raise FileNotFoundError(
                f"Cookie file not found: {cookie_file}. Export your UNIT3D session cookies in Netscape format."
            )

        cookie_jar = load_netscape_cookie_jar(cookie_file)
        self.session.cookies = cookie_jar

    def _build_upload_page_urls(self):
        configured_page_url = self.upload_config.get("page_url")
        if configured_page_url:
            return [configured_page_url]

        candidates = [
            urljoin(f"{self.base_url}/", "upload"),
            urljoin(f"{self.base_url}/", "torrents/create"),
        ]

        deduped = []
        seen = set()
        for candidate in candidates:
            normalized = str(candidate).rstrip("/")
            if normalized in seen:
                continue
            seen.add(normalized)
            deduped.append(candidate)
        return deduped

    def _load_upload_form_page(self):
        errors = []
        for candidate_url in self.upload_page_urls:
            response = self.session.get(candidate_url, timeout=self.timeout, allow_redirects=True)
            if not response.ok:
                errors.append(f"{candidate_url} -> HTTP {response.status_code}")
                continue
            if self._looks_like_login_page(response.url, response.text):
                raise ValueError("Upload page request appears unauthenticated. Check the exported cookie file.")

            submit_url = extract_upload_form_action(self.base_url, response.text)
            if submit_url:
                return response, submit_url

            errors.append(f"{candidate_url} -> no upload form with a torrent field was found")

        error_message = "; ".join(errors) if errors else "no candidate upload routes were tried"
        raise ValueError(f"Failed to load a UNIT3D upload form. Tried: {error_message}")

    def _resolve_release_profile(self, category_options, type_options, category_metadata=None, dry_run=False):
        default_category_id = self._infer_category_id(category_options) or next(iter(category_options.keys()), None)
        default_type_id = self._infer_type_id(type_options) or next(iter(type_options.keys()), None)
        if default_category_id is None or default_type_id is None:
            raise ValueError("The tracker upload form is missing category or type options.")

        should_prompt = self.upload_config.get("ask", True) and not dry_run
        category_id = default_category_id
        type_id = default_type_id
        anonymous = False
        personal_release = False
        ads_removed = False
        extra_keywords = []

        if should_prompt:
            category_id = choose_option("Select tracker category", category_options, default=default_category_id)
            type_id = choose_option("Select tracker type", type_options, default=default_type_id)
            anonymous = ask_yes_no_default("Upload anonymously", default=False)
            personal_release = ask_yes_no_default("Mark this as a personal release", default=False)
            ads_removed = ask_yes_no_default("Were ads removed without transcoding", default=False)
            extra_keywords = self._parse_extra_keywords(
                take_input("Extra upload keywords (comma separated, blank for none)")
            )

        type_name = type_options[str(type_id)]
        return ReleaseProfile(
            category_id=str(category_id),
            category_name=category_options[str(category_id)],
            category_kind=(category_metadata or {}).get(str(category_id), {}).get("type"),
            type_id=str(type_id),
            type_name=type_name,
            anonymous=anonymous,
            personal_release=personal_release,
            ads_removed=ads_removed,
            extra_keywords=extra_keywords,
            source_label=self._extract_source_label_from_type(type_name),
        )

    def _infer_category_id(self, options):
        tags = self.podcast.metadata.get_tags() or ""
        genres = (self.podcast.metadata.data or {}).get("genres", [])
        hints = set()
        for value in [self.podcast.name, tags, *genres]:
            normalized = normalize_tokens(value)
            if not normalized:
                continue
            hints.add(normalized)
            if "society culture" in normalized or ("society" in normalized and "culture" in normalized):
                hints.add("human interest")
            if "personal journals" in normalized:
                hints.add("human interest")

        best_option = None
        best_score = -1
        for option_id, label in options.items():
            normalized_label = normalize_tokens(label)
            label_tokens = set(normalized_label.split())
            score = 0
            for hint in hints:
                hint_tokens = set(hint.split())
                overlap = len(label_tokens & hint_tokens)
                if normalized_label == hint:
                    score = max(score, 6)
                elif hint in normalized_label or normalized_label in hint:
                    score = max(score, 4 + overlap)
                elif overlap:
                    score = max(score, overlap)
            if score > best_score:
                best_score = score
                best_option = option_id
        return str(best_option) if best_option is not None and best_score > 0 else None

    def _infer_type_id(self, options):
        signals = [
            self.upload_context.source_label or "",
            self.upload_context.name or "",
            self.podcast.name,
            self.podcast.metadata.get_rss_feed() or "",
        ]
        for file_path in sorted(self.podcast.folder_path.iterdir())[:30]:
            if file_path.is_file():
                signals.append(file_path.stem)
        joined = " ".join(signals).casefold()

        for keyword in ("patreon", "nebula", "premium", "memberful", "substack"):
            if keyword not in joined:
                continue
            for option_id, label in options.items():
                if keyword in label.casefold():
                    return str(option_id)

        for option_id, label in options.items():
            normalized_label = label.casefold()
            if "audio" in normalized_label and "free" in normalized_label:
                return str(option_id)
        return next(iter(options.keys()), None)

    def _build_payload(self, csrf_token, form_defaults=None):
        if not self.release_profile:
            raise ValueError("Release profile has not been resolved yet.")
        payload = dict(form_defaults or {})
        payload.update({
            "_token": csrf_token,
            "name": self.upload_context.name or self.upload_context.raw_name or self.podcast.name,
            "category_id": self.release_profile.category_id,
            "type_id": self.release_profile.type_id,
            "description": self.upload_context.description,
            "keywords": self.upload_context.keywords_string,
            "anon": "1" if self.release_profile.anonymous else "0",
            "personal_release": "1" if self.release_profile.personal_release else "0",
        })

        category_kind = (self.release_profile.category_kind or "no").casefold()
        if category_kind in {"movie", "tv"}:
            payload["stream"] = payload.get("stream", "0")
            payload["sd"] = payload.get("sd", "0")
            payload["tmdb"] = self._normalize_numeric_field(payload.get("tmdb"), default="0")
            payload["imdb"] = self._normalize_numeric_field(payload.get("imdb"), default="0")
            payload["mal"] = self._normalize_numeric_field(payload.get("mal"), default="0")
        else:
            payload["stream"] = "0"
            payload["sd"] = "0"
            payload["tmdb"] = "0"
            payload["imdb"] = "0"
            payload["mal"] = "0"

        if category_kind == "tv":
            payload["tvdb"] = self._normalize_numeric_field(payload.get("tvdb"), default="0")
            payload["season_number"] = self._infer_season_number()
            payload["episode_number"] = self._infer_episode_number()
        else:
            payload["tvdb"] = "0"
            payload.pop("season_number", None)
            payload.pop("episode_number", None)

        if category_kind == "game":
            payload["igdb"] = self._normalize_numeric_field(payload.get("igdb"), default="0")
        else:
            payload["igdb"] = "0"

        mediainfo = self.upload_context.data.get("mediainfo", {})
        if isinstance(mediainfo, dict):
            payload["mediainfo"] = mediainfo.get("output", "")
        else:
            payload["mediainfo"] = ""

        return payload

    def _normalize_numeric_field(self, value, default="0"):
        if value in (None, "", []):
            return default
        value_str = str(value).strip()
        if not value_str or not value_str.isdigit():
            return default
        return value_str

    def _infer_season_number(self):
        file_count = self.upload_context.data.get("number_of_files", 0)
        if file_count and file_count > 1:
            return "0"
        return "1"

    def _infer_episode_number(self):
        file_count = self.upload_context.data.get("number_of_files", 0)
        if file_count and file_count > 1:
            return "0"

        audio_files = sorted(
            file_path for file_path in self.podcast.folder_path.iterdir()
            if file_path.is_file() and file_path.suffix.lower() in {".m4a", ".mp3", ".mp4", ".m4b", ".flac", ".ogg"}
        )
        if audio_files:
            match = re.search(r"\[#?(\d+)\]", audio_files[0].stem)
            if not match:
                match = re.search(r"\b(\d+)\b", audio_files[0].stem)
            if match:
                return match.group(1)
        return "0"

    def _prepare_cover_image(self):
        cover_source = self._discover_cover_path()
        if not cover_source:
            if self.require_images:
                raise ValueError("No cover image was found automatically from the release files or remote metadata.")
            return None

        self._cover_source_path = Path(cover_source)
        output_path = self.temp_dir / "cover-upload.jpg"
        prepare_cover_image(cover_source, output_path)
        return output_path

    def _prepare_banner_image(self, nfo_path=None, cover_path=None, dry_run=False):
        banner_source = self._discover_banner_path()
        output_path = self.temp_dir / "banner-upload.jpg"
        size_budget = self._calculate_banner_budget(nfo_path=nfo_path, cover_path=cover_path)
        if banner_source:
            prepare_banner_image(banner_source, output_path, size_budget=size_budget)
            return output_path

        cover_source = self._cover_source_path or cover_path
        if cover_source:
            create_banner_from_cover(cover_source, output_path, size_budget=size_budget)
            self._asset_warnings.append("Banner image was auto-generated from the cover art because no widescreen artwork was found.")
            return output_path

        if self.upload_config.get("ask", True) and not dry_run:
            entered_path = take_input("Banner image not found automatically. Enter a path to a local banner image")
            resolved_path = self._resolve_path(entered_path)
            if resolved_path:
                prepare_banner_image(resolved_path, output_path, size_budget=size_budget)
                return output_path

        if self.require_images:
            raise ValueError("No banner image was found or derivable automatically.")
        return None

    def _parse_extra_keywords(self, raw_value):
        if not raw_value:
            return []
        return [keyword.strip() for keyword in raw_value.split(",") if keyword.strip()]

    def _extract_source_label_from_type(self, type_name):
        if not type_name:
            return None
        normalized = type_name.casefold()
        if "patreon" in normalized:
            return "Patreon"
        if "nebula" in normalized:
            return "Nebula"
        if "premium" in normalized:
            return "Premium"
        return None

    def _calculate_banner_budget(self, nfo_path=None, cover_path=None):
        total_fixed_bytes = self.torrent_path.stat().st_size + UPLOAD_SAFETY_MARGIN_BYTES
        if nfo_path:
            total_fixed_bytes += nfo_path.stat().st_size
        if cover_path:
            total_fixed_bytes += cover_path.stat().st_size
        budget = MAX_UPLOAD_BYTES - total_fixed_bytes
        if budget <= 0:
            raise ValueError(
                "The local torrent plus cover/NFO already exceed Unwalled's practical initial upload size budget. Increase piece size or shrink assets before uploading."
            )
        return budget

    def _discover_cover_path(self):
        metadata_dir = self.podcast.folder_path / self.config.get("metadata_directory", "Metadata")
        candidates = [
            self._find_named_file(metadata_dir, ["cover.jpg", "cover.jpeg", "cover.png", "cover.webp", "cover.avif"]),
            self._find_named_file(self.podcast.folder_path, ["cover.jpg", "cover.jpeg", "cover.png", "cover.webp", "cover.avif"]),
            self.podcast.image.get_meta_file_path(),
            self.podcast.image.get_file_path(),
            self.podcast.folder_path.parent / f"{self.podcast.folder_path.name}_cover.jpg",
        ]
        for candidate in candidates:
            if candidate and Path(candidate).exists():
                return Path(candidate)
        remote_cover = self._download_remote_image(self.podcast.metadata.get_image_url(), "cover-source")
        if remote_cover:
            return remote_cover
        return None

    def _discover_banner_path(self):
        metadata_dir = self.podcast.folder_path / self.config.get("metadata_directory", "Metadata")
        candidates = [
            self._find_named_file(metadata_dir, ["banner.jpg", "banner.jpeg", "banner.png", "banner.webp", "banner.avif"]),
            self._find_named_file(self.podcast.folder_path, ["banner.jpg", "banner.jpeg", "banner.png", "banner.webp", "banner.avif"]),
        ]
        for candidate in candidates:
            if candidate and Path(candidate).exists():
                return Path(candidate)

        remote_candidates = []
        public_link = self.podcast.metadata.get_public_link() or self.upload_context.source_url
        if public_link:
            remote_candidates.extend(self._extract_page_image_candidates(public_link))
        image_url = self.podcast.metadata.get_image_url()
        if image_url:
            remote_candidates.append(image_url)

        seen = set()
        for candidate_url in remote_candidates:
            if not candidate_url:
                continue
            marker = candidate_url.strip()
            if marker in seen:
                continue
            seen.add(marker)
            downloaded = self._download_remote_image(candidate_url, "banner-source")
            if downloaded and self._is_banner_candidate(downloaded):
                return downloaded
        return None

    def _discover_nfo_path(self):
        metadata_dir = self.podcast.folder_path / self.config.get("metadata_directory", "Metadata")
        candidates = [
            self._find_first_glob(self.podcast.folder_path, "*.nfo"),
            self._find_first_glob(metadata_dir, "*.nfo"),
        ]
        for candidate in candidates:
            if candidate and candidate.exists():
                return candidate
        return None

    def _resolve_path(self, path_value):
        if not path_value:
            return None
        candidate = Path(path_value).expanduser()
        search_roots = [Path.cwd(), self.podcast.folder_path, self.podcast.folder_path.parent]
        if candidate.is_absolute():
            return candidate if candidate.exists() else None

        for root in search_roots:
            resolved = root / candidate
            if resolved.exists():
                return resolved
        return None

    def _download_remote_image(self, image_url, prefix):
        if not image_url:
            return None
        try:
            response = self.session.get(image_url, timeout=self.timeout, allow_redirects=True)
        except requests.RequestException:
            return None
        if not response.ok or not response.content:
            return None
        suffix = image_suffix_from_response(image_url, response.headers.get("Content-Type"))
        output_path = self.temp_dir / f"{prefix}-{abs(hash(image_url))}{suffix}"
        output_path.write_bytes(response.content)
        return output_path

    def _extract_page_image_candidates(self, page_url):
        try:
            response = self.session.get(page_url, timeout=self.timeout, allow_redirects=True)
        except requests.RequestException:
            return []
        if not response.ok or "html" not in response.headers.get("Content-Type", "text/html"):
            return []

        soup = BeautifulSoup(response.text, "html.parser")
        candidates = []
        selectors = [
            ("meta", {"property": "og:image"}, "content"),
            ("meta", {"name": "twitter:image"}, "content"),
            ("link", {"rel": "image_src"}, "href"),
        ]
        for tag_name, attrs, value_key in selectors:
            node = soup.find(tag_name, attrs=attrs)
            if not node:
                continue
            value = node.get(value_key)
            if value:
                candidates.append(urljoin(page_url, value))
        return candidates

    def _is_banner_candidate(self, image_path):
        try:
            with Image.open(image_path) as image:
                width, height = image.size
        except Exception:
            return False
        if width < MIN_BANNER_SIZE[0] or height < MIN_BANNER_SIZE[1]:
            return False
        ratio = width / height
        return 1.55 <= ratio <= 2.2

    def _find_named_file(self, directory, names):
        directory = Path(directory)
        if not directory.exists() or not directory.is_dir():
            return None
        lowered = {name.lower() for name in names}
        for file_path in directory.iterdir():
            if file_path.is_file() and file_path.name.lower() in lowered:
                return file_path
        return None

    def _find_first_glob(self, directory, pattern):
        directory = Path(directory)
        if not directory.exists() or not directory.is_dir():
            return None
        for file_path in directory.iterdir():
            if file_path.is_file() and fnmatch(file_path.name.lower(), pattern.lower()):
                return file_path
        return None

    def _build_size_warnings(self, nfo_path=None, cover_path=None, banner_path=None):
        warnings = []
        total_bytes = self.torrent_path.stat().st_size
        if nfo_path:
            total_bytes += nfo_path.stat().st_size
        if cover_path:
            total_bytes += cover_path.stat().st_size
        if banner_path:
            total_bytes += banner_path.stat().st_size

        if total_bytes > MAX_UPLOAD_BYTES:
            warnings.append(
                "The initial upload payload is still above the tracker's practical 1 MB limit. The upload may fail until the banner or torrent is reduced further."
            )
        return warnings

    def _download_uploaded_torrent(self, download_url):
        response = self.session.get(download_url, timeout=self.timeout, allow_redirects=True)
        if not response.ok:
            raise ValueError(f"Upload succeeded but downloading the tracker torrent failed: HTTP {response.status_code}")

        tracker_torrent_path = self._build_tracker_torrent_path()
        if tracker_torrent_path.exists() and not ask_yes_no(f"Tracker torrent {tracker_torrent_path} already exists. Replace it?"):
            return tracker_torrent_path

        tracker_torrent_path.write_bytes(response.content)
        return tracker_torrent_path

    def _build_tracker_torrent_path(self):
        host = urlparse(self.base_url).netloc.replace(":", "_")
        return self.torrent_path.with_name(f"{self.torrent_path.stem}.{host}.tracker.torrent")

    def _looks_like_login_page(self, url, html):
        normalized_url = str(url).lower()
        if "/login" in normalized_url:
            return True
        soup = BeautifulSoup(html, "html.parser")
        if soup.find("form", {"action": re.compile("login", re.IGNORECASE)}):
            return True
        title = soup.title.string.strip().lower() if soup.title and soup.title.string else ""
        return "login" in title


def load_netscape_cookie_jar(cookie_file):
    cookie_jar = http.cookiejar.MozillaCookieJar(str(cookie_file))
    try:
        cookie_jar.load(ignore_discard=True, ignore_expires=True)
    except http.cookiejar.LoadError as error:
        raise ValueError(f"Failed to load Netscape cookie file {cookie_file}: {error}") from error
    return cookie_jar


def extract_csrf_token(html):
    soup = BeautifulSoup(html, "html.parser")
    token_input = soup.find("input", {"name": "_token"})
    if token_input and token_input.get("value"):
        return token_input.get("value")
    meta_tag = soup.find("meta", {"name": "csrf-token"})
    if meta_tag and meta_tag.get("content"):
        return meta_tag.get("content")
    return None


def parse_select_options(html, select_name):
    soup = BeautifulSoup(html, "html.parser")
    select = soup.find("select", {"name": select_name})
    if not select:
        return {}
    options = {}
    for option in select.find_all("option"):
        value = option.get("value")
        label = option.get_text(" ", strip=True)
        if value in (None, "") or not label:
            continue
        options[str(value)] = label
    return options


def parse_category_metadata(html):
    match = re.search(r"cats:\s*JSON\.parse\(atob\('([^']+)'\)\)", html)
    if not match:
        return {}
    try:
        decoded = base64_decode_json(match.group(1))
    except ValueError:
        return {}
    if not isinstance(decoded, dict):
        return {}
    metadata = {}
    for key, value in decoded.items():
        if isinstance(value, dict):
            metadata[str(key)] = value
    return metadata


def base64_decode_json(encoded_value):
    try:
        raw = base64.b64decode(encoded_value).decode("utf-8")
    except Exception as error:
        raise ValueError(f"Failed to decode base64 JSON: {error}") from error
    return json.loads(raw)


def extract_upload_form_action(base_url, html):
    soup = BeautifulSoup(html, "html.parser")
    for form in soup.find_all("form"):
        if form.find("input", {"name": "torrent"}):
            action = form.get("action")
            if action:
                return urljoin(f"{base_url}/", action)
    return None


def extract_form_defaults(html):
    soup = BeautifulSoup(html, "html.parser")
    target_form = None
    for form in soup.find_all("form"):
        if form.find("input", {"name": "torrent"}):
            target_form = form
            break
    if not target_form:
        return {}

    defaults = {}
    for field in target_form.find_all(["input", "textarea", "select"]):
        name = field.get("name")
        if not name:
            continue

        if field.name == "input":
            field_type = field.get("type", "text").lower()
            if field_type == "file":
                continue
            if field_type in {"checkbox", "radio"}:
                if field.has_attr("checked"):
                    defaults[name] = field.get("value") or "1"
                continue

            value = field.get("value")
            if value in (None, ""):
                continue
            if name not in defaults or defaults[name] == "":
                defaults[name] = value
            continue

        if field.name == "textarea":
            value = field.get_text(strip=True)
            if value and name not in defaults:
                defaults[name] = value
            continue

        if field.name == "select":
            selected = None
            for option in field.find_all("option"):
                if option.has_attr("selected"):
                    selected = option.get("value")
                    break
            if selected not in (None, ""):
                defaults[name] = selected

    return defaults


def extract_validation_errors(html):
    soup = BeautifulSoup(html, "html.parser")
    errors = []

    error_copy = soup.find(id="ERROR_COPY")
    if error_copy:
        errors.extend([line.strip() for line in error_copy.get_text("\n").splitlines() if line.strip()])

    for selector in ("li.auth-form__error", ".form__hint", ".text-red"):
        for node in soup.select(selector):
            text = node.get_text(" ", strip=True)
            if text:
                errors.append(text)

    deduped = []
    seen = set()
    for error in errors:
        marker = error.casefold()
        if marker in seen:
            continue
        seen.add(marker)
        deduped.append(error)
    return deduped


def extract_success_links(base_url, final_url, html):
    torrent_id = None
    download_url = None
    final_url = str(final_url)

    for pattern in (r"/download_check/(\d+)", r"/torrents/download/(\d+)", r"/download/(\d+)", r"/torrents/(\d+)"):
        match = re.search(pattern, final_url)
        if not match:
            continue
        torrent_id = match.group(1)
        if pattern in (r"/torrents/download/(\d+)", r"/download/(\d+)"):
            download_url = urljoin(f"{base_url}/", final_url)
        break

    if not torrent_id:
        soup = BeautifulSoup(html, "html.parser")
        for pattern in (r"/torrents/download/(\d+)", r"/download/(\d+)"):
            download_link = soup.find("a", href=re.compile(pattern))
            if not download_link or not download_link.get("href"):
                continue
            match = re.search(pattern, download_link.get("href"))
            if not match:
                continue
            torrent_id = match.group(1)
            download_url = urljoin(f"{base_url}/", download_link.get("href"))
            break

    if not torrent_id:
        return None, None

    details_url = urljoin(f"{base_url}/", f"torrents/{torrent_id}")
    if not download_url:
        download_url = urljoin(f"{base_url}/", f"torrents/download/{torrent_id}")
    return details_url, download_url


def normalize_tokens(value):
    return re.sub(r"\s+", " ", re.sub(r"[^a-z0-9]+", " ", str(value or "").casefold())).strip()


def image_suffix_from_response(image_url, content_type):
    suffix_map = {
        "image/jpeg": ".jpg",
        "image/png": ".png",
        "image/webp": ".webp",
        "image/avif": ".avif",
    }
    if content_type:
        normalized = content_type.split(";")[0].strip().casefold()
        if normalized in suffix_map:
            return suffix_map[normalized]
    suffix = Path(urlparse(image_url).path).suffix
    return suffix if suffix else ".img"


def prepare_cover_image(source_path, output_path):
    _prepare_image(
        source_path=source_path,
        output_path=output_path,
        target_size=DEFAULT_COVER_SIZE,
        min_size=(400, 400),
        size_budget=None,
    )


def prepare_banner_image(source_path, output_path, size_budget):
    _prepare_image(
        source_path=source_path,
        output_path=output_path,
        target_size=DEFAULT_BANNER_SIZE,
        min_size=MIN_BANNER_SIZE,
        size_budget=size_budget,
    )


def create_banner_from_cover(source_path, output_path, size_budget):
    source_path = Path(source_path)
    output_path = Path(output_path)
    with Image.open(source_path) as image:
        image = ImageOps.exif_transpose(image).convert("RGB")
        background = ImageOps.fit(image, DEFAULT_BANNER_SIZE, method=RESAMPLING_LANCZOS)
        background = background.filter(ImageFilter.GaussianBlur(radius=20))

        foreground = ImageOps.contain(image, (520, 520), method=RESAMPLING_LANCZOS)
        canvas = background.copy()
        x = (canvas.width - foreground.width) // 2
        y = (canvas.height - foreground.height) // 2
        shadow = Image.new("RGBA", canvas.size, (0, 0, 0, 0))
        shadow_block = Image.new("RGBA", (foreground.width + 28, foreground.height + 28), (0, 0, 0, 120))
        shadow.paste(shadow_block, (x - 14, y - 14))
        shadow = shadow.filter(ImageFilter.GaussianBlur(radius=14))
        canvas = Image.alpha_composite(canvas.convert("RGBA"), shadow).convert("RGB")
        canvas.paste(foreground, (x, y))

        quality_values = list(range(DEFAULT_IMAGE_QUALITY, MIN_IMAGE_QUALITY - 1, -QUALITY_STEP))
        size_candidates = [DEFAULT_BANNER_SIZE, (1152, 648), (1024, 576), MIN_BANNER_SIZE]
        for width, height in size_candidates:
            candidate = ImageOps.fit(canvas, (width, height), method=RESAMPLING_LANCZOS)
            for quality in quality_values:
                candidate.save(output_path, format="JPEG", quality=quality, optimize=True, progressive=True)
                if output_path.stat().st_size <= size_budget:
                    return output_path

    raise ValueError(
        f"Could not compress auto-generated banner derived from {source_path.name} below the required size budget ({size_budget} bytes)."
    )


def _prepare_image(source_path, output_path, target_size, min_size, size_budget=None):
    source_path = Path(source_path)
    output_path = Path(output_path)
    with Image.open(source_path) as image:
        image = ImageOps.exif_transpose(image).convert("RGB")
        quality_values = list(range(DEFAULT_IMAGE_QUALITY, MIN_IMAGE_QUALITY - 1, -QUALITY_STEP))
        size_candidates = [target_size]
        if target_size != min_size:
            size_candidates.extend([
                (1152, 648),
                (1024, 576),
                min_size,
            ])

        for width, height in size_candidates:
            candidate = ImageOps.fit(image, (width, height), method=RESAMPLING_LANCZOS)
            for quality in quality_values:
                candidate.save(output_path, format="JPEG", quality=quality, optimize=True, progressive=True)
                if size_budget is None or output_path.stat().st_size <= size_budget:
                    return output_path

    if size_budget is not None:
        raise ValueError(
            f"Could not compress {source_path.name} below the required size budget ({size_budget} bytes)."
        )
    raise ValueError(f"Could not prepare image {source_path}")
