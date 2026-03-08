import importlib.util
import tempfile
import unittest
from importlib.machinery import SourceFileLoader
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


SCRIPT_PATH = Path(__file__).resolve().parent.parent / "bulldozer"


def load_bulldozer_module():
    loader = SourceFileLoader("bulldozer_cli_test_module", str(SCRIPT_PATH))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


class BulldozerCliTest(unittest.TestCase):
    def test_create_torrent_skips_prompt_when_split_auto_apply_is_active(self):
        module = load_bulldozer_module()
        module.config = {
            "_runtime": {
                "split_auto_apply_remaining": True,
                "upload_requested": True,
                "upload_dry_run": False,
                "client_active": False,
            }
        }

        with tempfile.TemporaryDirectory() as temp_dir:
            folder_path = Path(temp_dir) / "Sample Podcast (2024)"
            folder_path.mkdir()
            (folder_path / "episode.mp3").write_bytes(b"episode")
            podcast = SimpleNamespace(name="Sample Podcast", folder_path=folder_path)

            with patch.object(module, "TorrentCreator") as torrent_creator_cls, patch.object(
                module,
                "ask_yes_no",
            ) as ask_yes_no:
                torrent_creator = torrent_creator_cls.return_value
                torrent_creator.calculate_piece_size.return_value = 21
                torrent_creator.create_torrent.return_value = Path(temp_dir) / "Sample Podcast (2024).torrent"

                result = module.create_torrent(
                    podcast,
                    "https://tracker.example/announce/key",
                    str(Path(temp_dir)),
                    None,
                )

        ask_yes_no.assert_not_called()
        torrent_creator.create_torrent.assert_called_once_with(21, replace_existing=True)
        self.assertTrue(str(result).endswith(".torrent"))


if __name__ == "__main__":
    unittest.main()
