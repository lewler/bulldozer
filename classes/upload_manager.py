from __future__ import annotations

from .upload_context import UploadContextBuilder
from .uploaders import Unit3DWebUploader
from .utils import announce, ask_yes_no, log


class UploadManager:
    def __init__(self, podcast, config, torrent_path):
        self.podcast = podcast
        self.config = config
        self.torrent_path = torrent_path
        self.upload_config = config.get("upload", {})

    def run(self, dry_run=False):
        if not self.podcast.metadata.has_data:
            self.podcast.metadata.load()
        upload_context = UploadContextBuilder(self.podcast, self.config).build()
        backend_name = self.upload_config.get("backend", "unit3d_web")
        if backend_name != "unit3d_web":
            raise ValueError(f"Unsupported upload backend: {backend_name}")

        uploader = Unit3DWebUploader(self.podcast, self.config, upload_context, self.torrent_path)
        try:
            preparation = uploader.run_preflight(dry_run=dry_run)
            self._print_preflight(uploader.upload_context, preparation, dry_run=dry_run)
            if dry_run:
                return

            should_ask = self.upload_config.get("ask", True)
            if should_ask and not ask_yes_no(f"Upload {uploader.upload_context.name} to {self.upload_config.get('base_url')} now"):
                announce("Upload cancelled.", "info")
                return

            result = uploader.submit(preparation)
        finally:
            uploader.cleanup()

        if result.success:
            announce(result.status_message, "celebrate")
            if result.tracker_torrent_path:
                announce(f"Tracker torrent saved to {result.tracker_torrent_path}", "info")
            return result

        if result.validation_errors:
            announce("Tracker validation errors:", "error")
            for error in result.validation_errors:
                announce(f"- {error}")
        if result.status_message:
            announce(result.status_message, "error")
        return result

    def _print_preflight(self, upload_context, preparation, dry_run=False):
        announce("Upload preflight summary:", "info")
        announce(f"Tracker: {self.upload_config.get('base_url')}", "info")
        announce(f"Title: {preparation.payload['name']}", "info")
        announce(f"Category: {preparation.category_name} ({preparation.payload['category_id']})", "info")
        announce(f"Type: {preparation.type_name} ({preparation.payload['type_id']})", "info")
        announce(f"Keywords: {preparation.payload['keywords'] or '(none)'}", "info")
        announce(f"Anonymous: {'yes' if preparation.payload['anon'] == '1' else 'no'}", "info")
        announce(f"Personal release: {'yes' if preparation.payload['personal_release'] == '1' else 'no'}", "info")
        announce(f"Torrent: {preparation.torrent_path}", "info")
        announce(f"Cover: {preparation.cover_path or '(none)'}", "info")
        announce(f"Banner: {preparation.banner_path or '(none)'}", "info")
        if preparation.nfo_path:
            announce(f"NFO: {preparation.nfo_path}", "info")
        if upload_context.source_url:
            announce(f"Source URL: {upload_context.source_url}", "info")
        for warning in preparation.warnings:
            announce(warning, "warning")
        if dry_run:
            announce("Dry run complete. Payload and assets validated without submitting to the tracker.", "celebrate")
        log(f"Prepared upload payload: {preparation.payload}", "debug")
