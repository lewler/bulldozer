import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from classes.upload_manager import UploadManager
from classes.uploaders.unit3d_web import UploadResult


class UploadManagerTest(unittest.TestCase):
    def test_run_skips_upload_confirmation_when_split_auto_apply_is_active(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            folder_path = Path(temp_dir) / "Sample Podcast (2024)"
            folder_path.mkdir()
            torrent_path = Path(temp_dir) / "Sample Podcast (2024).torrent"
            torrent_path.write_bytes(b"torrent")

            podcast = SimpleNamespace(
                folder_path=folder_path,
                metadata=SimpleNamespace(has_data=True),
            )
            upload_context = SimpleNamespace(
                name="Sample Podcast [2024/MP3 - 192kbps]",
                source_url="https://example.com/feed",
            )
            preparation = SimpleNamespace(
                payload={
                    "name": "Sample Podcast [2024/MP3 - 192kbps]",
                    "category_id": "27",
                    "type_id": "9",
                    "keywords": "news, tech.news",
                    "anon": "0",
                    "personal_release": "0",
                },
                warnings=[],
                category_name="Technology and Computing",
                type_name="Audio - Free",
                torrent_path=torrent_path,
                cover_path=None,
                banner_path=None,
                nfo_path=None,
            )

            uploader = Mock()
            uploader.run_preflight.return_value = preparation
            uploader.upload_context = upload_context
            uploader.submit.return_value = UploadResult(success=True, details_url="https://tracker/torrents/1")

            config = {
                "_runtime": {"split_auto_apply_remaining": True},
                "upload": {
                    "active": True,
                    "ask": True,
                    "backend": "unit3d_web",
                    "base_url": "https://tracker.example",
                },
                "client": {"active": False},
            }

            with patch("classes.upload_manager.UploadContextBuilder") as context_builder, patch(
                "classes.upload_manager.Unit3DWebUploader",
                return_value=uploader,
            ), patch("classes.upload_manager.ask_yes_no") as ask_yes_no, patch(
                "classes.upload_manager.mark_split_folder_completed"
            ):
                context_builder.return_value.build.return_value = upload_context
                result = UploadManager(podcast, config, torrent_path).run(dry_run=False)

        ask_yes_no.assert_not_called()
        uploader.submit.assert_called_once_with(preparation)
        self.assertTrue(result.success)


if __name__ == "__main__":
    unittest.main()
