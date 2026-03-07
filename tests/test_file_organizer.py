import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from classes.file_organizer import FileOrganizer


class FileOrganizerStagingTest(unittest.TestCase):
    def test_update_file_metadata_skips_hardlink_staging_to_protect_source(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            podcast_folder = Path(temp_dir) / "Podcast"
            podcast_folder.mkdir()
            (podcast_folder / "episode1.mp3").write_bytes(b"episode")

            organizer = FileOrganizer(
                SimpleNamespace(folder_path=podcast_folder),
                {
                    "file_metadata_replacements": [{"fields": ["title"], "pattern": "a", "replacement": "b"}],
                    "_staging_runtime": {
                        "active": True,
                        "mode": "hardlink",
                        "protect_source_content": True,
                    },
                },
            )

            with patch("classes.file_organizer.EasyID3") as easy_id3, patch("classes.file_organizer.MP4") as mp4:
                organizer.update_file_metadata()

            easy_id3.assert_not_called()
            mp4.assert_not_called()


if __name__ == "__main__":
    unittest.main()
