import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from classes.client_manager import QBittorrentClient


class QBittorrentClientTest(unittest.TestCase):
    def test_client_uses_environment_fallbacks(self):
        podcast = SimpleNamespace(folder_path=Path("/tmp/Wine About It 2023"))
        with patch.dict(
            os.environ,
            {
                "QBITTORRENT_URL": "http://127.0.0.1:18080",
                "QBITTORRENT_USERNAME": "admin",
                "QBITTORRENT_PASSWORD": "secret",
            },
            clear=True,
        ):
            client = QBittorrentClient(podcast, {})

        self.assertEqual(client.base_url, "http://127.0.0.1:18080")
        self.assertEqual(client.username, "admin")
        self.assertEqual(client.password, "secret")

    def test_add_torrent_posts_to_qbittorrent_with_parent_save_path(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            parent_path = Path(temp_dir) / "staging"
            parent_path.mkdir()
            podcast_folder = parent_path / "Wine About It 2023"
            podcast_folder.mkdir()
            torrent_path = Path(temp_dir) / "Wine About It 2023.tracker.torrent"
            torrent_path.write_bytes(b"d8:announce13:https://x/ee")

            podcast = SimpleNamespace(folder_path=podcast_folder)
            session = Mock()
            session.post.side_effect = [
                SimpleNamespace(status_code=200, text="Ok."),
                SimpleNamespace(status_code=200, text="Ok."),
            ]

            with patch("classes.client_manager.requests.Session", return_value=session):
                client = QBittorrentClient(
                    podcast,
                    {
                        "url": "http://127.0.0.1:18080",
                        "username": "admin",
                        "password": "secret",
                        "category": "podcasts",
                        "tags": ["unwalled", "patreon"],
                        "paused": False,
                        "skip_checking": False,
                    },
                )
                result = client.add_torrent(torrent_path)

        self.assertTrue(result.success)
        self.assertEqual(result.save_path, str(parent_path))
        self.assertEqual(session.post.call_count, 2)

        login_call = session.post.call_args_list[0]
        self.assertEqual(login_call.args[0], "http://127.0.0.1:18080/api/v2/auth/login")
        self.assertEqual(login_call.kwargs["data"], {"username": "admin", "password": "secret"})

        add_call = session.post.call_args_list[1]
        self.assertEqual(add_call.args[0], "http://127.0.0.1:18080/api/v2/torrents/add")
        self.assertEqual(add_call.kwargs["data"]["savepath"], str(parent_path))
        self.assertEqual(add_call.kwargs["data"]["autoTMM"], "false")
        self.assertEqual(add_call.kwargs["data"]["contentLayout"], "Original")
        self.assertEqual(add_call.kwargs["data"]["category"], "podcasts")
        self.assertEqual(add_call.kwargs["data"]["tags"], "unwalled,patreon")
        self.assertEqual(add_call.kwargs["data"]["paused"], "false")
        self.assertEqual(add_call.kwargs["data"]["skip_checking"], "false")
        self.assertIn("torrents", add_call.kwargs["files"])

    def test_add_torrent_uses_configured_save_path(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_root = Path(temp_dir)
            configured_save_path = temp_root / "grind"
            podcast_folder = temp_root / "staging" / "The WAN Show 2025"
            podcast_folder.mkdir(parents=True)
            torrent_path = temp_root / "The WAN Show 2025.tracker.torrent"
            torrent_path.write_bytes(b"d8:announce13:https://x/ee")

            podcast = SimpleNamespace(folder_path=podcast_folder)
            session = Mock()
            session.post.side_effect = [
                SimpleNamespace(status_code=200, text="Ok."),
                SimpleNamespace(status_code=200, text="Ok."),
            ]

            with patch("classes.client_manager.requests.Session", return_value=session):
                client = QBittorrentClient(
                    podcast,
                    {
                        "url": "http://127.0.0.1:18080",
                        "username": "admin",
                        "password": "secret",
                        "save_path": str(configured_save_path),
                    },
                )
                result = client.add_torrent(torrent_path)

        self.assertTrue(result.success)
        self.assertEqual(result.save_path, str(configured_save_path))
        add_call = session.post.call_args_list[1]
        self.assertEqual(add_call.kwargs["data"]["savepath"], str(configured_save_path))


if __name__ == "__main__":
    unittest.main()
