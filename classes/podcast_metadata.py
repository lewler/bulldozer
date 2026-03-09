# podcast_metadata.py
import json
import os
import re
import xml.etree.ElementTree as ET
from email.utils import parsedate_to_datetime
from pathlib import Path

import requests
from mutagen import File as MutagenFile

from .utils import log, archive_metadata, open_file_case_insensitive, find_case_insensitive_files
from .utils import copy_file
from .data_formatter import DataFormatter
from .apis.podchaser import Podchaser
from .apis.podcastindex import Podcastindex
from .scrapers.podnews import Podnews


ITUNES_SEARCH_URL = "https://itunes.apple.com/search"
ITUNES_NAMESPACES = {"itunes": "http://www.itunes.com/dtds/podcast-1.0.dtd"}

class PodcastMetadata:
    def __init__(self, podcast, config):
        """
        Initialize the PodcastMetadata with the podcast and configuration.

        :param podcast: The podcast object containing information about the podcast.
        :param config: The configuration

        The PodcastMetadata class is responsible for handling the podcast metadata file.
        """
        self.podcast = podcast
        self.config = config
        self.data = None
        self.external_data = {}
        self.has_data = False
        self.archive = config.get('archive_metadata', False)

    def get_file_path(self):
        """
        Get the path to the metadata file.

        :return: The path to the metadata file.
        """
        meta_files = find_case_insensitive_files('*.meta.*', self.podcast.folder_path)
        if not meta_files:
            return None
        file_path = self.podcast.folder_path / meta_files[0].name
        if not file_path.exists():
            return None
        return file_path

    def load(self, search_term=None):
        """
        Load the metadata from the file, and fetch data from the apis.

        :param search_term: The search term to use for finding the podcast.
        :return: True if the metadata was loaded successfully, False if there was an error, None if the file does not exist.
        """
        log(f"Loading metadata for {self.podcast.name}", "debug")
        if self.has_data:
            log(f"Metadata already loaded for {self.podcast.name}", "debug")
            return True
        
        status = None
        search_terms = self._build_search_terms(search_term)
        file_path = self.get_file_path()
        if file_path:
            try:
                with file_path.open() as f:
                    self.data = json.load(f)
                    self.has_data = True
                    status = True
            except json.JSONDecodeError as error:
                log(f"Invalid JSON in file '{file_path.name}'.", "error")
                log(error, "debug")
                status = False
        else:
            log(f"Metadata file for {self.podcast.name} does not exist. Falling back to dynamic metadata discovery.", "debug")
            self.data = self._load_fallback_metadata(search_terms)
            self.has_data = bool(self.data)
            status = True if self.data else None

        if self.has_data:
            self.fetch_additional_data(search_terms[0] if search_terms else search_term)
        self.check_if_podcast_is_complete()
        return status
    
    def check_if_podcast_is_complete(self):
        """
        Check if the podcast is complete based on the metadata.
        """
        if not self.external_data:
            self.podcast.completed = False

        if self.external_data.get('podchaser', {}).get('status', 'ACTIVE') != 'ACTIVE':
            self.podcast.completed = True
            return
        
        self.podcast.completed = False
        
    def format_data(self):
        """
        Format the metadata data using the DataFormatter.
        """
        formatter = DataFormatter(self.config)
        self.data = formatter.format_data(self.data)
        self.external_data = formatter.format_data(self.external_data)
        
    def fetch_additional_data(self, search_term=None):
        """
        Fetch additional metadata from APIs.
        """
        self.get_podchaser_data(search_term)
        self.get_podcastindex_data(search_term)
        self.get_podnews_data(search_term)
        self.format_data()

    def replace_description(self, description):
        """
        Replace parts of the description based on the configuration.

        :param description: The description to replace parts of.
        :return: The description with replacements made.
        """
        replacements = self.config.get('description_replacements', [])
        for replacement in replacements:
            pattern = replacement['pattern']
            repl = replacement['replace_with']
            escaped_pattern = re.escape(pattern)
            description = re.sub(escaped_pattern, repl, description)
        if description and description[0] == '\n':
            description = description[1:]
        if description and description[-1] == '\n':
            description = description[:-1]
        return description.strip()

    def get_description(self):
        """
        Get the description from the metadata.

        :return: The description from the metadata.
        """
        if not self.data:
            return None

        description = self.data.get('description')
        if not description:
            return None

        return self.replace_description(description)

    def get_links(self):
        """
        Get the links from the metadata.

        :return: The links from the metadata.
        """
        if not self.data:
            return None

        links = {}
        candidates = [
            ("Official Website", self.data.get("link")),
            ("Apple Podcasts", self.data.get("collectionViewUrl") or self.data.get("itunesPageURL")),
            ("RSS Feed", _sanitize_public_metadata_url(self.get_rss_feed())),
            ("Podchaser", self.external_data.get("podchaser", {}).get("webUrl") or self.external_data.get("podchaser", {}).get("url")),
            ("Podcast Index", _build_podcastindex_url(self.external_data.get("podcastindex", {}).get("id"))),
            ("Podnews", self.external_data.get("podnews", {}).get("url")),
        ]
        for label, value in candidates:
            if isinstance(value, str) and value.strip():
                links[label] = value.strip()
        return links

    def get_tags(self):
        """
        Get the tags from the metadata.

        :return: The tags from the metadata.
        """
        if not self.data:
            return None
        
        categories = []
        if "itunes" in self.data and "categories" in self.data["itunes"]:
            categories = self.data["itunes"]["categories"]
        elif self.data.get("genres"):
            categories = self.data["genres"]
        if not categories:
            return None

        processed_categories = []
        for category in categories:
            parts = category.lower().split('&')
            processed_categories.extend([part.strip() for part in parts])

        explicit = None
        if "itunes" in self.data:
            explicit = self.data["itunes"].get("explicit")
        if explicit in (True, "true", "yes"):
            processed_categories.append("explicit")

        return ', '.join(processed_categories)

    def get_rss_feed(self):
        """
        Get the RSS feed URL from the metadata.

        :return: The RSS feed URL from the metadata.
        """
        if not self.data:
            return None
        
        return self.data.get('feedUrl') or self.data.get('feedURL') or self.data.get('rssUrl')

    def get_image_url(self):
        """
        Get the primary cover image URL from the loaded metadata.

        :return: The image URL if available.
        """
        if not self.data:
            return None
        candidates = [
            self.data.get("imageUrl"),
            self.data.get("imageURL"),
            self.data.get("artworkUrl600"),
            self.data.get("artworkUrl100"),
        ]
        for candidate in candidates:
            if isinstance(candidate, str) and candidate.strip():
                return candidate.strip()
        return None

    def get_public_link(self):
        """
        Get the best public-facing podcast URL.

        :return: The public link if available.
        """
        if not self.data:
            return None
        candidates = [
            self.data.get("link"),
            self.data.get("collectionViewUrl"),
            self.data.get("itunesPageURL"),
            self.data.get("webUrl"),
            self.data.get("url"),
        ]
        for candidate in candidates:
            if isinstance(candidate, str) and candidate.strip():
                return candidate.strip()
        return None

    def _build_search_terms(self, search_term=None):
        candidates = []

        def add(value):
            if not value:
                return
            normalized = re.sub(r"\s+", " ", str(value)).strip()
            if not normalized:
                return
            marker = normalized.casefold()
            if marker not in {item.casefold() for item in candidates}:
                candidates.append(normalized)

        add(search_term)
        add(getattr(self.podcast, "search_term", None))
        add(self.podcast.get_clean_name())
        add(self.podcast.name)

        for value in list(candidates):
            simplified = value
            simplified = re.sub(r"\b(19|20)\d{2}\b(?:\s*(?:to|through|-)\s*\b(19|20)\d{2}\b)?", "", simplified, flags=re.IGNORECASE)
            simplified = re.sub(r"\bto\s+date\b", "", simplified, flags=re.IGNORECASE)
            simplified = re.sub(r"\s*\([^)]*\)\s*", " ", simplified)
            simplified = re.sub(r"\s{2,}", " ", simplified).strip(" -")
            add(simplified)

        return candidates

    def _load_fallback_metadata(self, search_terms):
        loaders = [
            self._load_lookup_metadata,
            self._search_itunes_metadata,
            self._load_embedded_audio_metadata,
        ]
        for loader in loaders:
            try:
                data = loader(search_terms)
            except Exception as error:
                log(f"Dynamic metadata discovery via {loader.__name__} failed: {error}", "debug")
                continue
            if data:
                log(f"Loaded metadata for {self.podcast.name} via {loader.__name__}", "debug")
                return data
        return None

    def _load_lookup_metadata(self, search_terms):
        roots = []
        for configured_path in self.config.get("metadata_lookup_paths", []):
            if configured_path:
                roots.append(Path(configured_path).expanduser())

        env_path = os.environ.get("AUDIOBOOKSHELF_METADATA_DIR")
        if env_path:
            roots.append(Path(env_path).expanduser())

        default_abs_path = Path("/mnt/Pool/Services/Data/audiobookshelf/metadata/items")
        if default_abs_path.exists():
            roots.append(default_abs_path)

        seen_roots = set()
        best_match = None
        best_score = -1
        for root in roots:
            if not root.exists():
                continue
            root_key = str(root.resolve())
            if root_key in seen_roots:
                continue
            seen_roots.add(root_key)
            for metadata_file in root.rglob("metadata.json"):
                try:
                    data = json.loads(metadata_file.read_text(encoding="utf-8"))
                except (OSError, json.JSONDecodeError):
                    continue
                title = data.get("title") or data.get("name")
                score = _score_title_match(title, search_terms)
                if score > best_score:
                    best_match = data
                    best_score = score

        if not best_match or best_score < 2:
            return None
        return _normalize_lookup_metadata(best_match)

    def _search_itunes_metadata(self, search_terms):
        best_result = None
        best_score = -1
        for term in search_terms:
            response = requests.get(
                ITUNES_SEARCH_URL,
                params={"media": "podcast", "entity": "podcast", "limit": 8, "term": term},
                timeout=15,
            )
            if not response.ok:
                continue
            for item in response.json().get("results", []):
                score = _score_title_match(item.get("collectionName"), search_terms)
                if item.get("artistName"):
                    score += _score_title_match(item.get("artistName"), search_terms) * 0.15
                if score > best_score:
                    best_result = item
                    best_score = score
            if best_score >= 4:
                break

        if not best_result or best_score < 2:
            return None

        normalized = _normalize_itunes_metadata(best_result)
        rss_feed = normalized.get("feedUrl")
        if rss_feed:
            rss_data = self._load_rss_channel_metadata(rss_feed)
            if rss_data:
                normalized = _merge_metadata(normalized, rss_data)
        return normalized

    def _load_rss_channel_metadata(self, feed_url):
        try:
            response = requests.get(feed_url, timeout=15)
        except requests.RequestException as error:
            log(f"RSS metadata fetch failed for {feed_url}: {error}", "debug")
            return None
        if not response.ok:
            return None

        try:
            root = ET.fromstring(response.content)
        except ET.ParseError as error:
            log(f"RSS metadata parse failed for {feed_url}: {error}", "debug")
            return None

        channel = root.find("./channel")
        if channel is None:
            return None

        categories = []
        for category in channel.findall("itunes:category", ITUNES_NAMESPACES):
            text = category.attrib.get("text")
            if text:
                categories.append(text)
            for child in category.findall("itunes:category", ITUNES_NAMESPACES):
                child_text = child.attrib.get("text")
                if child_text:
                    categories.append(child_text)

        image_url = None
        itunes_image = channel.find("itunes:image", ITUNES_NAMESPACES)
        if itunes_image is not None:
            image_url = itunes_image.attrib.get("href")
        if not image_url:
            image = channel.find("image/url")
            if image is not None and image.text:
                image_url = image.text.strip()

        description_node = (
            channel.find("itunes:summary", ITUNES_NAMESPACES)
            or channel.find("description")
        )
        description = description_node.text.strip() if description_node is not None and description_node.text else None

        link_node = channel.find("link")
        language_node = channel.find("language")
        explicit_node = channel.find("itunes:explicit", ITUNES_NAMESPACES)

        return {
            "description": description,
            "link": link_node.text.strip() if link_node is not None and link_node.text else None,
            "language": language_node.text.strip() if language_node is not None and language_node.text else None,
            "feedUrl": feed_url,
            "imageUrl": image_url,
            "itunes": {
                "categories": categories,
                "explicit": explicit_node.text.strip().lower() if explicit_node is not None and explicit_node.text else None,
            },
        }

    def _load_embedded_audio_metadata(self, search_terms):
        audio_files = []
        for pattern in ("*.m4a", "*.mp3", "*.mp4", "*.m4b", "*.flac", "*.ogg"):
            audio_files.extend(sorted(self.podcast.folder_path.glob(pattern)))
        if not audio_files:
            return None

        for audio_file in audio_files[:8]:
            tags = _extract_embedded_tags(audio_file)
            if not tags:
                continue
            title = tags.get("album") or tags.get("title") or self.podcast.get_clean_name()
            if _score_title_match(title, search_terms) < 1:
                continue
            return _normalize_embedded_metadata(tags)
        return None
    
    def get_external_data(self, api_name, api_class, search_term, *args):
        """
        Get the data for the podcast from a specified API.
        
        :param api_name: Name of the API (e.g., 'podchaser', 'podcastindex').
        :param api_class: The class for interacting with the API (e.g., Podchaser, Podcastindex).
        :param search_term: The search term to use for finding the podcast.
        :param args: Additional arguments required for the API class constructor.
        """
        api_config = self.config.get(api_name, {})
        log(f"Getting {api_name.capitalize()} data for {self.podcast.name}", "debug")
        
        if not api_config.get('active', False):
            log(f"{api_name.capitalize()} API is not enabled.", "debug")
            return None
        
        if not search_term:
            search_term = self.podcast.name

        api_instance = api_class(*args)
        podcast = api_instance.find_podcast(search_term)
        
        if not podcast:
            self.external_data[api_name] = {}
            return False
        
        self.external_data[api_name] = podcast
        self.has_data = True
        return True
    
    def get_podchaser_data(self, search_term=None):
        """
        Get the Podchaser data for the podcast.

        :param search_term: The search term to use for finding the podcast.
        """
        return self.get_external_data(
            'podchaser',
            Podchaser,
            search_term,
            self.config.get('podchaser', {}).get('client_id', None),
            self.config.get('podchaser', {}).get('client_secret', None),
            self.config.get('podchaser', {}).get('fields', None),
            self.config.get('podchaser', {}).get('url', None),
            self.config.get('podchaser', {}).get('limit', 25),
            self.config.get('cache', {}).get('directory', None)
        )
    
    def get_podcastindex_data(self, search_term=None):
        """
        Get the Podcastindex data for the podcast.

        :param search_term: The search term to use for finding the podcast.
        """
        return self.get_external_data(
            'podcastindex',
            Podcastindex,
            search_term,
            self.config.get('podcastindex', {}).get('key', None),
            self.config.get('podcastindex', {}).get('secret', None),
            self.config.get('podcastindex', {}).get('url', None)
        )
    
    def get_podnews_data(self, search_term=None):
        """
        Get the Podnews data for the podcast.

        :param search_term: The search term to use for finding the podcast.
        """
        return self.get_external_data(
            'podnews',
            Podnews,
            search_term,
            self.config.get('podnews', {}).get('url', None)
        )
    
    def archive_file(self):
        """
        Archive the metadata file.

        If the archive_metadata configuration is set to True, the metadata file will be archived instead of deleted.
        """
        file_path = self.get_file_path()
        
        if not file_path:
            log(f"Metadata file {file_path} does not exist.", "debug")
            return
        
        if not self.archive:
            log(f"Deleting meta {file_path.name}", "debug")
            file_path.unlink()
            return

        archive_folder = self.config.get('archive_metadata_directory', None)
        archive_metadata(file_path, archive_folder)
        log(f"Deleting meta {file_path.name}", "debug")
        file_path.unlink()

    def duplicate(self, new_folder):
        """
        Duplicate the metadata file to a new folder.

        :param new_folder: The folder to duplicate the metadata file to.
        """
        file_path = self.get_file_path()
        
        if not file_path:
            log(f"Metadata file {file_path} does not exist - can't duplicate.", "debug")
            return
        
        new_file_path = new_folder / file_path.name
        copy_file(file_path, new_file_path)
        log(f"Duplicated meta {file_path.name} to {new_file_path}", "debug")

    def get_external_ids(self):
        ids = []
        for dataset in self.external_data.values():
            ids.append(dataset.get('id'))
        return ids


def _normalize_lookup_text(value):
    normalized = re.sub(r"[^a-z0-9]+", " ", str(value or "").casefold())
    return re.sub(r"\s+", " ", normalized).strip()


def _score_title_match(candidate, search_terms):
    normalized_candidate = _normalize_lookup_text(candidate)
    if not normalized_candidate:
        return 0

    score = 0
    for term in search_terms:
        normalized_term = _normalize_lookup_text(term)
        if not normalized_term:
            continue
        if normalized_candidate == normalized_term:
            score = max(score, 5)
            continue
        candidate_tokens = set(normalized_candidate.split())
        term_tokens = set(normalized_term.split())
        overlap = len(candidate_tokens & term_tokens)
        if normalized_term in normalized_candidate or normalized_candidate in normalized_term:
            score = max(score, 3 + overlap)
        elif overlap:
            score = max(score, overlap)
    return score


def _normalize_lookup_metadata(raw):
    genres = [genre for genre in raw.get("genres", []) if genre and genre.lower() != "podcasts"]
    return {
        "title": raw.get("title") or raw.get("name"),
        "author": raw.get("author"),
        "description": raw.get("description"),
        "link": raw.get("itunesPageURL") or raw.get("link"),
        "feedUrl": raw.get("feedURL") or raw.get("feedUrl"),
        "imageUrl": raw.get("imageURL") or raw.get("imageUrl"),
        "language": raw.get("language"),
        "genres": genres,
        "itunes": {
            "categories": genres,
            "explicit": "yes" if raw.get("explicit") else "no",
        },
    }


def _normalize_itunes_metadata(raw):
    genres = [genre for genre in raw.get("genres", []) if genre and genre.lower() != "podcasts"]
    if not genres and raw.get("primaryGenreName"):
        genres = [raw["primaryGenreName"]]
    return {
        "title": raw.get("collectionName"),
        "author": raw.get("artistName"),
        "description": raw.get("description"),
        "link": raw.get("artistViewUrl"),
        "collectionViewUrl": raw.get("collectionViewUrl"),
        "feedUrl": raw.get("feedUrl"),
        "imageUrl": raw.get("artworkUrl600") or raw.get("artworkUrl100"),
        "artworkUrl600": raw.get("artworkUrl600"),
        "artworkUrl100": raw.get("artworkUrl100"),
        "releaseDate": raw.get("releaseDate"),
        "genres": genres,
        "itunes": {
            "categories": genres,
            "explicit": "yes" if raw.get("trackExplicitness") == "explicit" else None,
        },
    }


def _merge_metadata(base, override):
    merged = dict(base or {})
    for key, value in (override or {}).items():
        if value in (None, "", [], {}):
            continue
        if isinstance(value, dict):
            merged[key] = _merge_metadata(merged.get(key, {}), value)
        else:
            merged[key] = value
    return merged


def _extract_embedded_tags(audio_file):
    try:
        media = MutagenFile(audio_file)
    except Exception as error:
        log(f"Failed to read embedded tags from {audio_file.name}: {error}", "debug")
        return None
    if not media or not getattr(media, "tags", None):
        return None

    tags = media.tags
    extracted = {
        "album": _first_tag_value(tags, ["©alb", "TALB"]),
        "title": _first_tag_value(tags, ["©nam", "TIT2"]),
        "author": _first_tag_value(tags, ["©ART", "TPE1"]),
        "genre": _first_tag_value(tags, ["©gen", "TCON"]),
        "description": _first_tag_value(tags, ["desc", "TXXX:comment", "COMM::eng"]),
        "language": _first_tag_value(tags, ["TLAN"]),
        "release_date": _first_tag_value(tags, ["©day", "TDRC", "TXXX:releasedate"]),
    }
    return extracted


def _first_tag_value(tags, keys):
    for key in keys:
        if key not in tags:
            continue
        raw_value = tags.get(key)
        if isinstance(raw_value, list):
            raw_value = raw_value[0] if raw_value else None
        if hasattr(raw_value, "text"):
            raw_value = raw_value.text[0] if raw_value.text else None
        if raw_value is None:
            continue
        value = str(raw_value).strip()
        if value:
            return value
    return None


def _normalize_embedded_metadata(tags):
    categories = [tags["genre"]] if tags.get("genre") else []
    description = tags.get("description")
    if description:
        description = re.sub(r"<[^>]+>", "", description).strip()

    release_date = tags.get("release_date")
    if release_date:
        try:
            release_date = parsedate_to_datetime(release_date).isoformat()
        except (TypeError, ValueError):
            release_date = str(release_date)

    return {
        "title": tags.get("album"),
        "author": tags.get("author"),
        "description": description,
        "language": tags.get("language"),
        "releaseDate": release_date,
        "genres": categories,
        "itunes": {
            "categories": categories,
            "explicit": None,
        },
    }


def _build_podcastindex_url(podcast_id):
    if podcast_id in (None, ""):
        return None
    return f"https://podcastindex.org/podcast/{podcast_id}"


def _sanitize_public_metadata_url(url):
    if not url:
        return None
    candidate = str(url).strip()
    if not candidate:
        return None

    match = re.match(r"https?://(?:www\.)?patreon\.com/rss/([^/?#]+)", candidate, flags=re.IGNORECASE)
    if match:
        return f"https://www.patreon.com/{match.group(1)}"

    sanitized = re.sub(r"([?&])(auth|token|key|apikey|api_key|rss_token)=[^&#]+", "", candidate, flags=re.IGNORECASE)
    return sanitized.replace("?&", "?").rstrip("?&")
