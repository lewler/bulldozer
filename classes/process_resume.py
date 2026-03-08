from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from .client_manager import ClientManager
from .report import Report
from .split_run_state import find_existing_local_torrent, find_existing_tracker_torrent, get_split_folder_record
from .torrent_creator import TorrentCreator


@dataclass
class ProcessResumeStatus:
    label_text: str
    processed: bool
    report_path: Path
    report_exists: bool
    local_torrent_path: Path | None
    local_torrent_exists: bool
    tracker_torrent_path: Path | None
    upload_exists: bool
    upload_details_url: str | None
    client_present: bool
    client_save_path: str | None = None
    client_infohash: str | None = None

    @property
    def any_prior_step(self):
        return any(
            [
                self.processed,
                self.report_exists,
                self.local_torrent_exists,
                self.upload_exists,
                self.client_present,
            ]
        )


def build_redo_plan(step_status, mode, *, upload_requested=False, client_active=False):
    redo_all = mode == "redo_all"
    return {
        "redo_processing": bool(redo_all and step_status.processed),
        "redo_report": bool(redo_all and step_status.report_exists),
        "redo_torrent": bool(redo_all and step_status.local_torrent_exists),
        "redo_upload": bool(redo_all and upload_requested and step_status.upload_exists),
        "redo_client": bool(redo_all and client_active and step_status.client_present),
    }


def inspect_process_resume_status(podcast, config, announce_url=None, base_dir=None, tracker_source=None):
    label_text = build_folder_label(podcast.folder_path.name)
    report = Report(podcast, config)
    report_path = report.get_file_path()
    report_exists = report_path.exists()

    local_torrent_path = None
    local_torrent_exists = False
    if announce_url:
        torrent_creator = TorrentCreator(podcast, announce_url, base_dir, tracker_source)
        local_torrent_path = torrent_creator.get_torrent_path()
        local_torrent_exists = local_torrent_path.exists()
        if not local_torrent_exists:
            state_path = (config.get("_runtime", {}).get("split_state") or {}).get("path")
            if state_path:
                discovered_local_torrent = find_existing_local_torrent(config, state_path, podcast.folder_path.name)
                if discovered_local_torrent:
                    local_torrent_path = discovered_local_torrent
                    local_torrent_exists = True

    folder_record = get_split_folder_record(config, podcast.folder_path) or {}
    tracker_torrent_path = None
    record_tracker_torrent_path = folder_record.get("tracker_torrent_path")
    if record_tracker_torrent_path:
        candidate = Path(record_tracker_torrent_path)
        if candidate.exists():
            tracker_torrent_path = candidate
    if tracker_torrent_path is None:
        state_path = (config.get("_runtime", {}).get("split_state") or {}).get("path")
        if state_path:
            tracker_torrent_path = find_existing_tracker_torrent(config, state_path, podcast.folder_path.name)

    upload_exists = bool(folder_record) or bool(tracker_torrent_path)
    upload_details_url = folder_record.get("details_url")
    processed = bool(folder_record.get("processed_at"))

    client_present = bool(folder_record.get("client_present", False))
    client_save_path = folder_record.get("client_save_path")
    client_infohash = folder_record.get("client_infohash")
    inspect_torrent_path = tracker_torrent_path or local_torrent_path
    try:
        client_status = ClientManager(podcast, config).inspect(inspect_torrent_path)
    except Exception:
        client_status = None
    if client_status:
        client_present = client_status.present
        client_save_path = client_status.save_path
        client_infohash = client_status.infohash
    if not processed:
        processed = any([report_exists, local_torrent_exists, upload_exists, client_present])

    return ProcessResumeStatus(
        label_text=label_text,
        processed=processed,
        report_path=report_path,
        report_exists=report_exists,
        local_torrent_path=local_torrent_path,
        local_torrent_exists=local_torrent_exists,
        tracker_torrent_path=tracker_torrent_path,
        upload_exists=upload_exists,
        upload_details_url=upload_details_url,
        client_present=client_present,
        client_save_path=client_save_path,
        client_infohash=client_infohash,
    )


def build_folder_label(folder_name):
    match = re.search(r"(19|20)\d{2}", folder_name)
    if match:
        return f"year {match.group(0)}"
    return folder_name
