import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from classes.split_run_state import (
    backfill_completed_folders,
    bind_runtime_split_state,
    get_split_folder_paths,
    get_remaining_split_paths,
    get_split_state_path,
    initialize_split_state,
    load_split_state,
    mark_split_folder_completed,
    mark_split_folder_processed,
    remember_upload_prompt_defaults,
)


class SplitRunStateTest(unittest.TestCase):
    def test_completed_years_are_skipped_on_resume(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            staging_root = Path(temp_dir)
            split_a = staging_root / "Sample Podcast (2024)"
            split_b = staging_root / "Sample Podcast (2025)"
            split_c = staging_root / "Sample Podcast (2026)"
            for folder in (split_a, split_b, split_c):
                folder.mkdir()

            state_path = get_split_state_path(staging_root, "Sample Podcast")
            state = initialize_split_state(
                state_path,
                "/library/Sample Podcast",
                "yearly",
                [split_a, split_b, split_c],
            )
            config = {"_runtime": {}}
            bind_runtime_split_state(config, state_path, state)
            mark_split_folder_completed(
                config,
                split_a,
                result=SimpleNamespace(details_url="https://tracker/torrents/1", download_url=None, tracker_torrent_path=None),
            )
            mark_split_folder_completed(
                config,
                split_b,
                result=SimpleNamespace(details_url="https://tracker/torrents/2", download_url=None, tracker_torrent_path=None),
            )

            remaining = get_remaining_split_paths(state_path)

            self.assertEqual(remaining, [split_c])

    def test_prompt_defaults_persist_into_split_state(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            staging_root = Path(temp_dir)
            split_a = staging_root / "Sample Podcast (2024)"
            split_a.mkdir()
            state_path = get_split_state_path(staging_root, "Sample Podcast")
            state = initialize_split_state(
                state_path,
                "/library/Sample Podcast",
                "yearly",
                [split_a],
            )
            config = {"_runtime": {}}
            bind_runtime_split_state(config, state_path, state)

            remember_upload_prompt_defaults(
                config,
                category_id="31",
                type_id="7",
                anonymous=False,
                personal_release=False,
                ads_removed=False,
                extra_keywords=["wine.about.it"],
            )

            reloaded = load_split_state(state_path)
            self.assertEqual(
                reloaded["last_prompt_defaults"],
                {
                    "category_id": "31",
                    "type_id": "7",
                    "anonymous": False,
                    "personal_release": False,
                    "ads_removed": False,
                    "extra_keywords": ["wine.about.it"],
                },
            )

    def test_backfill_completed_folders_from_tracker_torrents(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            grind_root = root / "grind"
            grind_root.mkdir()
            legacy_root = root / ".unwalled-wine-about-it"
            legacy_root.mkdir()

            split_a = grind_root / "Sample Podcast (2024)"
            split_b = grind_root / "Sample Podcast (2025)"
            split_c = grind_root / "Sample Podcast (2026)"
            for folder in (split_a, split_b, split_c):
                folder.mkdir()

            (legacy_root / "Sample Podcast (2024).tracker.example.tracker.torrent").write_text("a")
            (legacy_root / "Sample Podcast (2025).tracker.example.tracker.torrent").write_text("b")

            state_path = get_split_state_path(grind_root, "Sample Podcast")
            state = initialize_split_state(
                state_path,
                "/library/Sample Podcast",
                "yearly",
                [split_a, split_b, split_c],
            )
            state = backfill_completed_folders(
                {
                    "staging": {"path": str(grind_root)},
                    "client": {"save_path": str(grind_root)},
                    "upload": {"base_url": "https://tracker.example"},
                },
                state_path,
                state,
            )

            self.assertEqual(set(state["completed_folders"].keys()), {"Sample Podcast (2024)", "Sample Podcast (2025)"})
            self.assertEqual(get_remaining_split_paths(state_path, state), [split_c])

    def test_mark_processed_persists_and_survives_completion(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            staging_root = Path(temp_dir)
            split_a = staging_root / "Sample Podcast (2024)"
            split_a.mkdir()
            state_path = get_split_state_path(staging_root, "Sample Podcast")
            state = initialize_split_state(
                state_path,
                "/library/Sample Podcast",
                "yearly",
                [split_a],
            )
            config = {"_runtime": {}}
            bind_runtime_split_state(config, state_path, state)

            processed_record = mark_split_folder_processed(config, split_a)
            self.assertIn("processed_at", processed_record)

            mark_split_folder_completed(
                config,
                split_a,
                result=SimpleNamespace(details_url="https://tracker/torrents/1", download_url=None, tracker_torrent_path=None),
            )

            reloaded = load_split_state(state_path)
            self.assertIn("processed_at", reloaded["completed_folders"]["Sample Podcast (2024)"])
            self.assertEqual(
                reloaded["completed_folders"]["Sample Podcast (2024)"]["details_url"],
                "https://tracker/torrents/1",
            )

    def test_get_split_folder_paths_separates_existing_and_missing(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            staging_root = Path(temp_dir)
            split_a = staging_root / "Sample Podcast (2024)"
            split_b = staging_root / "Sample Podcast (2025)"
            split_c = staging_root / "Sample Podcast (2026)"
            split_a.mkdir()
            split_c.mkdir()

            state_path = get_split_state_path(staging_root, "Sample Podcast")
            state = initialize_split_state(
                state_path,
                "/library/Sample Podcast",
                "yearly",
                [split_a, split_b, split_c],
            )

            existing, missing = get_split_folder_paths(state_path, state)

            self.assertEqual(existing, [split_a, split_c])
            self.assertEqual(missing, [split_b])


if __name__ == "__main__":
    unittest.main()
