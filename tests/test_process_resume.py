import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from classes.process_resume import build_redo_plan, inspect_process_resume_status
from classes.split_run_state import bind_runtime_split_state, get_split_state_path, initialize_split_state, mark_split_folder_processed


class ProcessResumeStatusTest(unittest.TestCase):
    def make_podcast(self, folder_path):
        return SimpleNamespace(
            folder_path=Path(folder_path),
            metadata=SimpleNamespace(has_data=False),
        )

    def test_processed_is_inferred_from_existing_artifacts(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            folder = root / "Sample Podcast (2024)"
            folder.mkdir()
            (root / "Sample Podcast (2024).txt").write_text("report")
            (root / "Sample Podcast (2024).torrent").write_text("torrent")

            podcast = self.make_podcast(folder)
            status = inspect_process_resume_status(
                podcast,
                {"client": {"active": False}},
                announce_url="https://tracker.example/announce/key",
                base_dir=str(root),
            )

            self.assertTrue(status.processed)
            self.assertTrue(status.report_exists)
            self.assertTrue(status.local_torrent_exists)

    def test_build_redo_plan_redoes_all_completed_steps(self):
        status = SimpleNamespace(
            processed=True,
            report_exists=True,
            local_torrent_exists=True,
            upload_exists=True,
            client_present=True,
        )

        plan = build_redo_plan(status, "redo_all", upload_requested=True, client_active=True)

        self.assertEqual(
            plan,
            {
                "redo_processing": True,
                "redo_report": True,
                "redo_torrent": True,
                "redo_upload": True,
                "redo_client": True,
            },
        )

    def test_build_redo_plan_skips_everything_when_mode_is_skip(self):
        status = SimpleNamespace(
            processed=True,
            report_exists=True,
            local_torrent_exists=True,
            upload_exists=True,
            client_present=True,
        )

        plan = build_redo_plan(status, "skip", upload_requested=True, client_active=True)

        self.assertEqual(
            plan,
            {
                "redo_processing": False,
                "redo_report": False,
                "redo_torrent": False,
                "redo_upload": False,
                "redo_client": False,
            },
        )

    def test_processed_uses_split_state_marker_when_present(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            folder = root / "Sample Podcast (2024)"
            folder.mkdir()
            state_path = get_split_state_path(root, "Sample Podcast")
            state = initialize_split_state(
                state_path,
                "/library/Sample Podcast",
                "yearly",
                [folder],
            )
            config = {"_runtime": {}, "client": {"active": False}}
            bind_runtime_split_state(config, state_path, state)
            mark_split_folder_processed(config, folder)

            podcast = self.make_podcast(folder)
            status = inspect_process_resume_status(
                podcast,
                config,
                announce_url="https://tracker.example/announce/key",
                base_dir=str(root),
            )

            self.assertTrue(status.processed)


if __name__ == "__main__":
    unittest.main()
