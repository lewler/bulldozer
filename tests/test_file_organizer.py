import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

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


class FileOrganizerSortableFilenameTest(unittest.TestCase):
    def make_podcast(self, temp_dir, rss_titles=None):
        podcast_folder = Path(temp_dir) / "The WAN Show"
        podcast_folder.mkdir()
        analyzer = SimpleNamespace(
            update_file_path=Mock(),
            file_dates={},
            original_files={},
        )
        return SimpleNamespace(
            folder_path=podcast_folder,
            name="The WAN Show",
            analyzer=analyzer,
            rss=SimpleNamespace(get_episodes=Mock(return_value=rss_titles or [])),
        )

    def test_apply_sortable_audio_filename_uses_plain_date_prefix_without_brackets(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            podcast = self.make_podcast(temp_dir)
            organizer = FileOrganizer(podcast, {})
            file_path = podcast.folder_path / "JIBO IS DEAD!! - The WAN Show Nov 30 2018.mp3"
            file_path.write_text("episode")

            new_path = organizer.apply_sortable_audio_filename(file_path, "2018-11-30")

            self.assertEqual(new_path.name, "2018-11-30 JIBO IS DEAD!!.mp3")
            self.assertTrue(new_path.exists())
            self.assertFalse(file_path.exists())

    def test_apply_sortable_audio_filename_strips_episode_number_when_date_is_unique(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            podcast = self.make_podcast(temp_dir)
            organizer = FileOrganizer(podcast, {})
            podcast.analyzer.file_dates = {"2019-06-08": [podcast.folder_path / "old.mp3"]}
            file_path = podcast.folder_path / "2019-06-08 Ep. 07 - Let's Talk About The Mac Stand... - WAN Show.mp3"
            file_path.write_text("episode")

            new_path = organizer.apply_sortable_audio_filename(file_path, "2019-06-08")

            self.assertEqual(new_path.name, "2019-06-08 Let's Talk About The Mac Stand... - WAN Show.mp3")
            self.assertTrue(new_path.exists())
            self.assertFalse(file_path.exists())

    def test_assign_episode_numbers_from_rss_uses_plain_date_prefix_without_brackets(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            podcast = self.make_podcast(temp_dir, rss_titles=["Bent iPad Pros"])
            organizer = FileOrganizer(podcast, {"trailer_patterns": ["trailer"]})
            file_path = podcast.folder_path / "Bent iPad Pros - The WAN Show Dec 21 2018.mp3"
            file_path.write_text("episode")

            organizer.assign_episode_numbers_from_rss({"2018-12-21": [file_path]})

            new_path = podcast.folder_path / "2018-12-21 Ep. 1 - Bent iPad Pros.mp3"
            self.assertTrue(new_path.exists())
            podcast.analyzer.update_file_path.assert_called_once_with(file_path, new_path)


class FileOrganizerSplitTest(unittest.TestCase):
    def make_podcast(self, temp_dir):
        podcast_folder = Path(temp_dir) / "Sample Podcast"
        podcast_folder.mkdir()
        old_file = podcast_folder / "2025 episode.mp3"
        current_file = podcast_folder / "2026 episode.mp3"
        old_file.write_text("old")
        current_file.write_text("current")

        analyzer = SimpleNamespace(
            earliest_year=2025,
            last_episode_date="2026-02-01",
            file_dates={
                "2025-08-01": [old_file],
                "2026-02-01": [current_file],
            },
            remove_file=Mock(),
        )
        podcast = SimpleNamespace(
            completed=False,
            name="Sample Podcast",
            folder_path=podcast_folder,
            analyzer=analyzer,
            analyze_files=None,
            metadata=SimpleNamespace(duplicate=Mock()),
            image=SimpleNamespace(duplicate=Mock()),
            rss=SimpleNamespace(duplicate=Mock()),
            split_folder_paths=None,
        )

        def analyze_files():
            rebased = {}
            for date, files in analyzer.file_dates.items():
                rebased[date] = [podcast.folder_path / file_path.name for file_path in files]
            analyzer.file_dates = rebased

        podcast.analyze_files = Mock(side_effect=analyze_files)
        return podcast, old_file, current_file

    def patch_current_year(self, year):
        return patch("classes.file_organizer.datetime", autospec=True, **{"now.return_value": SimpleNamespace(year=year)})

    def test_check_split_does_not_prompt_when_not_interactive(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            podcast, old_file, current_file = self.make_podcast(temp_dir)
            organizer = FileOrganizer(podcast, {"split": False})

            with self.patch_current_year(2026), \
                patch("classes.file_organizer.is_interactive_terminal", return_value=False), \
                patch("classes.file_organizer.choose_option") as choose_option:
                organizer.check_split()

            choose_option.assert_not_called()
            self.assertTrue(old_file.exists())
            self.assertTrue(current_file.exists())
            self.assertFalse((podcast.folder_path.parent / "Sample Podcast --CURRENT--").exists())

    def test_check_split_leaves_folder_untouched_when_user_skips(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            podcast, old_file, current_file = self.make_podcast(temp_dir)
            organizer = FileOrganizer(podcast, {"split": False})

            with self.patch_current_year(2026), \
                patch("classes.file_organizer.is_interactive_terminal", return_value=True), \
                patch("classes.file_organizer.choose_option", return_value="skip") as choose_option:
                organizer.check_split()

            choose_option.assert_called_once()
            self.assertTrue(old_file.exists())
            self.assertTrue(current_file.exists())
            self.assertFalse((podcast.folder_path.parent / "Sample Podcast --CURRENT--").exists())

    def test_check_split_uses_interactive_selection_for_last_full_year(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            podcast, old_file, current_file = self.make_podcast(temp_dir)
            organizer = FileOrganizer(podcast, {"split": False})

            with self.patch_current_year(2026), \
                patch("classes.file_organizer.is_interactive_terminal", return_value=True), \
                patch("classes.file_organizer.choose_option", return_value="last_full_year") as choose_option:
                split_paths = organizer.check_split()

            current_folder = podcast.folder_path.parent / "Sample Podcast --CURRENT--"

            choose_option.assert_called_once()
            self.assertEqual(split_paths, [podcast.folder_path, current_folder])
            self.assertTrue(old_file.exists())
            self.assertFalse(current_file.exists())
            self.assertTrue((current_folder / "2026 episode.mp3").exists())
            podcast.analyzer.remove_file.assert_called_once_with(current_file)
            podcast.metadata.duplicate.assert_called_once_with(current_folder)
            podcast.image.duplicate.assert_called_once_with(current_folder)
            podcast.rss.duplicate.assert_called_once_with(current_folder)

    def test_check_split_skips_prompt_for_single_year_packs(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            podcast, old_file, current_file = self.make_podcast(temp_dir)
            podcast.analyzer.earliest_year = 2026
            organizer = FileOrganizer(podcast, {"split": False})

            with self.patch_current_year(2026), \
                patch("classes.file_organizer.is_interactive_terminal", return_value=True), \
                patch("classes.file_organizer.choose_option") as choose_option:
                organizer.check_split()

            choose_option.assert_not_called()
            self.assertTrue(old_file.exists())
            self.assertTrue(current_file.exists())

    def test_check_split_defaults_to_yearly_during_upload_automation(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            podcast, _, _ = self.make_podcast(temp_dir)
            organizer = FileOrganizer(
                podcast,
                {
                    "split": False,
                    "upload": {"active": True},
                    "client": {"active": True},
                },
            )

            with self.patch_current_year(2026), \
                patch("classes.file_organizer.is_interactive_terminal", return_value=True), \
                patch("classes.file_organizer.choose_option", return_value="yearly") as choose_option:
                organizer.check_split()

            self.assertEqual(choose_option.call_args.kwargs["default"], "yearly")

    def test_check_split_yearly_replaces_existing_targets(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            podcast, old_file, current_file = self.make_podcast(temp_dir)
            organizer = FileOrganizer(podcast, {"split": False})
            stale_start_year = podcast.folder_path.parent / "Sample Podcast (2025)"
            stale_current_year = podcast.folder_path.parent / "Sample Podcast (2026)"
            stale_start_year.mkdir()
            stale_current_year.mkdir()
            (stale_start_year / "stale.txt").write_text("old")
            (stale_current_year / "stale.txt").write_text("old")

            with self.patch_current_year(2026), \
                patch("classes.file_organizer.is_interactive_terminal", return_value=True), \
                patch("classes.file_organizer.choose_option", return_value="yearly"), \
                patch("classes.file_organizer.ask_yes_no", return_value=True) as ask_yes_no:
                split_paths = organizer.check_split()

            self.assertEqual(split_paths, [stale_start_year, stale_current_year])
            self.assertTrue((stale_start_year / "2025 episode.mp3").exists())
            self.assertTrue((stale_current_year / "2026 episode.mp3").exists())
            self.assertFalse((stale_start_year / "stale.txt").exists())
            self.assertFalse((stale_current_year / "stale.txt").exists())
            self.assertEqual(ask_yes_no.call_count, 2)

    def test_check_split_yearly_auto_replaces_existing_targets_during_staging(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            podcast, _, _ = self.make_podcast(temp_dir)
            organizer = FileOrganizer(
                podcast,
                {
                    "split": False,
                    "staging": {"active": True, "overwrite": True},
                    "_staging_runtime": {"active": True},
                },
            )
            stale_start_year = podcast.folder_path.parent / "Sample Podcast (2025)"
            stale_current_year = podcast.folder_path.parent / "Sample Podcast (2026)"
            stale_start_year.mkdir()
            stale_current_year.mkdir()
            (stale_start_year / "stale.txt").write_text("old")
            (stale_current_year / "stale.txt").write_text("old")

            with self.patch_current_year(2026), \
                patch("classes.file_organizer.is_interactive_terminal", return_value=True), \
                patch("classes.file_organizer.choose_option", return_value="yearly"), \
                patch("classes.file_organizer.ask_yes_no") as ask_yes_no:
                split_paths = organizer.check_split()

            self.assertEqual(split_paths, [stale_start_year, stale_current_year])
            self.assertTrue((stale_start_year / "2025 episode.mp3").exists())
            self.assertTrue((stale_current_year / "2026 episode.mp3").exists())
            ask_yes_no.assert_not_called()


if __name__ == "__main__":
    unittest.main()
