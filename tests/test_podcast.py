import tempfile
import unittest
from pathlib import Path

from classes.podcast import Podcast


class PodcastCleanupTest(unittest.TestCase):
    def make_podcast(self, folder_path, config=None, source_is_local_folder=False):
        podcast = Podcast.__new__(Podcast)
        podcast.folder_path = Path(folder_path)
        podcast.config = config or {}
        podcast.source_is_local_folder = source_is_local_folder
        return podcast

    def test_cleanup_does_not_delete_unstaged_local_folder_input(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            folder_path = Path(temp_dir) / "Podcast"
            folder_path.mkdir()

            podcast = self.make_podcast(folder_path, config={}, source_is_local_folder=True)

            with self.assertRaises(SystemExit):
                podcast.cleanup_and_exit()

            self.assertTrue(folder_path.exists())

    def test_cleanup_removes_staged_local_folder_input(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            folder_path = Path(temp_dir) / "Podcast"
            folder_path.mkdir()

            podcast = self.make_podcast(
                folder_path,
                config={"_staging_runtime": {"active": True, "mode": "hardlink"}},
                source_is_local_folder=True,
            )

            with self.assertRaises(SystemExit):
                podcast.cleanup_and_exit()

            self.assertFalse(folder_path.exists())


if __name__ == "__main__":
    unittest.main()
