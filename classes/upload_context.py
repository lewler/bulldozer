from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field

from .report_template import ReportTemplate
from .utils import format_last_date, log


@dataclass
class UploadContext:
    data: dict
    name: str | None
    raw_name: str | None
    report_text: str
    description: str
    keywords: list[str] = field(default_factory=list)
    keywords_string: str = ""
    source_label: str | None = None
    source_url: str | None = None
    warnings: list[str] = field(default_factory=list)


@dataclass
class ReleaseProfile:
    category_id: str | None = None
    category_name: str | None = None
    category_kind: str | None = None
    type_id: str | None = None
    type_name: str | None = None
    anonymous: bool = False
    personal_release: bool = False
    ads_removed: bool = False
    extra_keywords: list[str] = field(default_factory=list)
    source_label: str | None = None


class UploadContextBuilder:
    def __init__(self, podcast, config):
        self.podcast = podcast
        self.config = config
        self.template = ReportTemplate(podcast, config)

    def build(self, check_files_only=False, release_profile=None):
        data = self._build_data(check_files_only)
        source_label = None
        if release_profile and release_profile.source_label:
            source_label = release_profile.source_label
        if not source_label:
            source_label = self._extract_source_label(data.get("premium_show", ""))
        raw_name = self.template.get_name(data) if data else None
        name = sanitize_upload_title(raw_name, source_label) if raw_name else None
        if name:
            data["name"] = name

        source_url = self._extract_source_url()
        upload_notes = self._build_upload_notes(source_label, source_url, release_profile)
        if upload_notes:
            data["upload_notes"] = upload_notes

        keywords = [] if check_files_only else build_upload_keywords(
            tags=data.get("tags"),
            source_label=source_label,
            extra_keywords=getattr(release_profile, "extra_keywords", None),
            ads_removed=getattr(release_profile, "ads_removed", False),
        )
        keywords_string = ", ".join(keywords)

        warnings = [] if check_files_only else self._build_warnings()
        report_text = self.template.render(data).lstrip("\n")
        description = self.template.render_tracker_description(data).lstrip("\n")

        return UploadContext(
            data=data,
            name=name,
            raw_name=raw_name,
            report_text=report_text,
            description=description,
            keywords=keywords,
            keywords_string=keywords_string,
            source_label=source_label,
            source_url=source_url,
            warnings=warnings,
        )

    def _build_data(self, check_files_only=False):
        cutoff = self.config.get("cutoff", 0.5)
        bitrates_counter = Counter()
        for bitrate_str, files in self.podcast.analyzer.bitrates.items():
            bitrates_counter[bitrate_str] = len(files)

        if not bitrates_counter:
            raise ValueError("No analyzed bitrate data available for upload context generation")

        total_files = sum(bitrates_counter.values())
        most_common_bitrate, most_common_bitrate_count = bitrates_counter.most_common(1)[0]
        if most_common_bitrate_count > total_files * cutoff:
            overall_bitrate = most_common_bitrate
        elif self.podcast.analyzer.all_vbr:
            overall_bitrate = "VBR"
        else:
            overall_bitrate = "Mixed"

        file_formats_counter = Counter()
        for file_format, files in self.podcast.analyzer.file_formats.items():
            file_formats_counter[file_format] = len(files)

        if not file_formats_counter:
            raise ValueError("No analyzed file format data available for upload context generation")

        most_common_file_format, most_common_file_format_count = file_formats_counter.most_common(1)[0]
        if most_common_file_format_count > total_files * cutoff:
            file_format = most_common_file_format
        else:
            file_format = "Mixed"

        start_year_str = str(self.podcast.analyzer.earliest_year) if self.podcast.analyzer.earliest_year else "Unknown"
        first_episode_date_str = self._format_date(self.podcast.analyzer.first_episode_date)
        real_first_episode_date_str = self._format_date(self.podcast.analyzer.real_first_episode_date)
        last_episode_date_str = self._format_date(self.podcast.analyzer.last_episode_date)
        real_last_episode_date_str = self._format_date(self.podcast.analyzer.real_last_episode_date)

        if self.podcast.completed and last_episode_date_str and last_episode_date_str != "Unknown":
            last_episode_year = last_episode_date_str.split()[-1]
            if start_year_str == last_episode_year:
                last_episode_date_str = ""

        if file_format != "Mixed":
            file_format = file_format.upper()

        end_year_string = last_episode_date_str.split()[-1] if last_episode_date_str else ""

        data = {
            "start_year_str": start_year_str,
            "end_year_str": end_year_string,
            "first_episode_date": self.podcast.analyzer.first_episode_date,
            "real_first_episode_date": self.podcast.analyzer.real_first_episode_date,
            "last_episode_date": self.podcast.analyzer.last_episode_date,
            "real_last_episode_date": self.podcast.analyzer.real_last_episode_date,
            "first_episode_date_str": first_episode_date_str,
            "real_first_episode_date_str": real_first_episode_date_str,
            "last_episode_date_str": last_episode_date_str,
            "real_last_episode_date_str": real_last_episode_date_str,
            "file_format": file_format,
            "overall_bitrate": overall_bitrate,
            "completed": self.podcast.completed,
            "number_of_files": total_files,
            "average_duration": self.podcast.analyzer.get_average_duration(),
            "longest_duration": self.podcast.analyzer.get_longest_duration(),
            "shortest_duration": self.podcast.analyzer.get_shortest_duration(),
            "name_clean": self.podcast.name,
            "premium_show": self.podcast.rss.check_for_premium_show(),
        }

        if not check_files_only:
            tags = self.podcast.metadata.get_tags()
            if tags:
                data["tags"] = tags

            description = self.podcast.metadata.get_description()
            if description:
                data["description"] = description

            data["last_episode_included"] = self.podcast.analyzer.last_episode_date

        bitrate_breakdown = ""
        if overall_bitrate == "Mixed" or check_files_only:
            sorted_bitrates = sorted(
                bitrates_counter.keys(),
                key=lambda bitrate: float(bitrate.replace(" kbps", "")) if "kbps" in bitrate else float("inf"),
            )
            for bitrate in sorted_bitrates:
                bitrate_breakdown += f"{bitrate}:\n"
                for file_path in sorted(self.podcast.analyzer.bitrates[bitrate]):
                    bitrate_breakdown += f"  {file_path.name}\n"
        if bitrate_breakdown:
            data["bitrate_breakdown"] = bitrate_breakdown[:-1]

        differing_bitrates = ""
        if len(bitrates_counter) > 1 and not self.podcast.analyzer.all_vbr and overall_bitrate != "Mixed" and not check_files_only:
            for bitrate, files in self.podcast.analyzer.bitrates.items():
                if bitrate != most_common_bitrate:
                    differing_bitrates += f"{bitrate}:\n"
                    for file_path in files:
                        differing_bitrates += f"  {file_path.name}\n"
        if differing_bitrates:
            data["differing_bitrates"] = differing_bitrates[:-1]

        file_format_breakdown = ""
        if file_format == "Mixed" or check_files_only:
            for current_format, _ in file_formats_counter.items():
                file_format_breakdown += f"{current_format.upper()}:\n"
                for file_path in self.podcast.analyzer.file_formats[current_format]:
                    file_format_breakdown += f"  {file_path.name}\n"
        if file_format_breakdown:
            data["file_format_breakdown"] = file_format_breakdown[:-1]

        differing_file_formats = ""
        if len(file_formats_counter) > 1 and file_format != "Mixed" and not check_files_only:
            for current_format, files in self.podcast.analyzer.file_formats.items():
                if current_format != most_common_file_format:
                    differing_file_formats += f"{current_format.upper()}:\n"
                    for file_path in files:
                        differing_file_formats += f"  {file_path.name}\n"
        if differing_file_formats:
            data["differing_file_formats"] = differing_file_formats[:-1]

        if not check_files_only:
            links = self.podcast.metadata.get_links()
            if links:
                data["links"] = self.template.get_links(links)

            for site, external_data in self.podcast.metadata.external_data.items():
                data[site] = external_data

            if self.podcast.analyzer.mediainfo_output:
                data["mediainfo"] = self.podcast.analyzer.mediainfo_output

        log(f"Upload context data: {data}", "debug")
        return data

    def _format_date(self, date_property):
        if not date_property:
            return "Unknown"
        return format_last_date(date_property, self.config.get("date_format_long", "%B %d %Y"))

    def _extract_source_label(self, premium_show):
        if not premium_show:
            return None
        label = premium_show.strip()
        if label.startswith("(") and label.endswith(")"):
            label = label[1:-1].strip()
        return label or None

    def _extract_source_url(self):
        metadata = self.podcast.metadata.data or {}
        external = self.podcast.metadata.external_data or {}
        candidates = [
            metadata.get("link"),
            metadata.get("collectionViewUrl"),
            metadata.get("itunesPageURL"),
            metadata.get("webUrl"),
            metadata.get("url"),
            metadata.get("feedUrl"),
            external.get("podchaser", {}).get("webUrl"),
            external.get("podchaser", {}).get("url"),
            external.get("podcastindex", {}).get("link"),
            external.get("podcastindex", {}).get("url"),
            external.get("podnews", {}).get("url"),
        ]
        for candidate in candidates:
            if isinstance(candidate, str) and candidate.strip():
                public_url = sanitize_public_source_url(candidate)
                if public_url:
                    return public_url
        return None

    def _build_upload_notes(self, source_label, source_url, release_profile=None):
        lines = []
        if source_label:
            lines.append(f"[b]Source:[/b] {source_label}")
        if source_url:
            lines.append(f"[b]Source Link:[/b] [url={source_url}]{source_url}[/url]")
        if getattr(release_profile, "ads_removed", False):
            lines.append("[b]Note:[/b] Adverts were removed by the uploader without transcoding.")
        return "\n".join(lines)

    def _build_warnings(self):
        warnings = []
        language = self._extract_language()
        if language and not language.lower().startswith("en"):
            warnings.append(
                "This podcast appears to be non-English. Unwalled requires an English translation in the title and description."
            )
        if self.config.get("upload", {}).get("require_images", True):
            warnings.append("Confirm the banner image is relevant, 16:9, and not AI-generated before uploading.")
        return warnings

    def _extract_language(self):
        metadata = self.podcast.metadata.data or {}
        external = self.podcast.metadata.external_data or {}
        candidates = [
            metadata.get("language"),
            external.get("podchaser", {}).get("language"),
            external.get("podcastindex", {}).get("language"),
        ]
        for candidate in candidates:
            if isinstance(candidate, str) and candidate.strip():
                return candidate.strip()
        return None


def sanitize_upload_title(title, source_label=None):
    if not title:
        return title

    sanitized = re.sub(r"\s+", " ", title).strip()
    if source_label in {"Patreon", "Nebula"}:
        sanitized = re.sub(rf"\s*\({re.escape(source_label)}\)", "", sanitized, flags=re.IGNORECASE)

    sanitized = sanitized.replace("&", "and")
    sanitized = re.sub(
        r"/([A-Za-z0-9]+)\s*-\s*([^\]]+)\]",
        lambda match: f"/{match.group(1).upper()} - {_normalize_bitrate_label(match.group(2))}]",
        sanitized,
    )
    sanitized = re.sub(
        r"/([A-Za-z0-9]+)-([^\]]+)\]",
        lambda match: f"/{match.group(1).upper()} - {_normalize_bitrate_label(match.group(2))}]",
        sanitized,
    )
    sanitized = re.sub(r"(\d+)\s+kbps", r"\1kbps", sanitized, flags=re.IGNORECASE)
    sanitized = re.sub(r"\s+", " ", sanitized).strip()
    return sanitized


def build_upload_keywords(tags=None, source_label=None, extra_keywords=None, ads_removed=False):
    values = []
    if tags:
        values.extend([item.strip() for item in tags.split(",") if item.strip()])

    values.extend(extra_keywords or [])
    if source_label:
        values.append(source_label)
    if ads_removed:
        values.append("ads.removed")

    normalized = []
    seen = set()
    for value in values:
        keyword = normalize_keyword(value)
        if not keyword:
            continue
        marker = keyword.casefold()
        if marker in seen:
            continue
        seen.add(marker)
        normalized.append(keyword)
    return normalized


def normalize_keyword(keyword):
    if keyword is None:
        return None
    normalized = str(keyword).strip()
    if not normalized:
        return None
    normalized = normalized.replace("&", "and")
    normalized = re.sub(r"\s+", " ", normalized)
    if " " in normalized and "." not in normalized:
        normalized = normalized.replace(" ", ".")
    normalized = re.sub(r"\.{2,}", ".", normalized)
    return normalized.strip(" ,.")


def _normalize_bitrate_label(value):
    normalized = re.sub(r"(\d+)\s+kbps", r"\1kbps", value.strip(), flags=re.IGNORECASE)
    return normalized


def sanitize_public_source_url(url):
    if not url:
        return None

    candidate = str(url).strip()
    if not candidate:
        return None

    match = re.match(r"https?://(?:www\.)?patreon\.com/rss/([^/?#]+)", candidate, flags=re.IGNORECASE)
    if match:
        return f"https://www.patreon.com/{match.group(1)}"

    sanitized = re.sub(r"([?&])(auth|token|key|apikey|api_key|rss_token)=[^&#]+", "", candidate, flags=re.IGNORECASE)
    sanitized = sanitized.replace("?&", "?").rstrip("?&")
    return sanitized
