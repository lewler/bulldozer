import tempfile
import unittest
from pathlib import Path

from classes.staging_manager import StagingManager


class StagingManagerTest(unittest.TestCase):
    def test_prepare_returns_original_path_when_disabled(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            source = Path(temp_dir) / "Podcast"
            source.mkdir()

            staged = StagingManager({"staging": {"active": False}}).prepare(source)

            self.assertEqual(staged, source.resolve())

    def test_prepare_hardlinks_local_folder_into_staging_root(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_root = Path(temp_dir)
            source = temp_root / "Podcast"
            nested = source / "Metadata"
            nested.mkdir(parents=True)
            (source / "episode1.m4a").write_bytes(b"episode-1")
            (nested / "podcast.rss").write_text("<rss></rss>", encoding="utf-8")

            staging_root = temp_root / "staging"
            manager = StagingManager(
                {
                    "staging": {
                        "active": True,
                        "path": str(staging_root),
                        "mode": "hardlink",
                        "overwrite": True,
                    }
                }
            )

            staged = manager.prepare(source)

            self.assertEqual(staged, (staging_root / "Podcast").resolve())
            staged_episode = staged / "episode1.m4a"
            staged_rss = staged / "Metadata" / "podcast.rss"
            self.assertTrue(staged_episode.exists())
            self.assertTrue(staged_rss.exists())
            self.assertEqual((source / "episode1.m4a").stat().st_ino, staged_episode.stat().st_ino)
            self.assertEqual((nested / "podcast.rss").stat().st_ino, staged_rss.stat().st_ino)

    def test_prepare_uses_default_hidden_staging_root_when_forced(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_root = Path(temp_dir)
            source = temp_root / "Podcast"
            source.mkdir()
            (source / "episode1.m4a").write_bytes(b"episode-1")

            manager = StagingManager({"staging": {"active": False, "mode": "hardlink"}})
            staged = manager.prepare(source, force=True)

            self.assertEqual(staged, (temp_root / ".bulldozer-staging" / "Podcast").resolve())
            self.assertEqual((source / "episode1.m4a").stat().st_ino, (staged / "episode1.m4a").stat().st_ino)
            self.assertTrue(manager.config["_staging_runtime"]["active"])
            self.assertEqual(manager.config["_staging_runtime"]["mode"], "hardlink")


if __name__ == "__main__":
    unittest.main()
