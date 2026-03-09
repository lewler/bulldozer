import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from PIL import Image

from classes.upload_context import ReleaseProfile
from classes.uploaders.unit3d_web import (
    create_banner_from_cover,
    parse_category_metadata,
    extract_csrf_token,
    extract_form_defaults,
    extract_upload_form_action,
    extract_success_links,
    extract_validation_errors,
    load_netscape_cookie_jar,
    parse_select_options,
    prepare_banner_image,
    prepare_cover_image,
    Unit3DWebUploader,
)


FIXTURES = Path(__file__).parent / "fixtures"


class Unit3DWebHelpersTest(unittest.TestCase):
    def test_load_netscape_cookie_jar(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            cookie_file = Path(temp_dir) / "cookies.txt"
            cookie_file.write_text(
                "\n".join(
                    [
                        "# Netscape HTTP Cookie File",
                        ".unwalled.cc\tTRUE\t/\tFALSE\t2147483647\tsession\tabc123",
                    ]
                ),
                encoding="utf-8",
            )
            cookie_jar = load_netscape_cookie_jar(cookie_file)
            self.assertEqual(len(cookie_jar), 1)
            self.assertEqual(next(iter(cookie_jar)).name, "session")

    def test_extract_csrf_and_select_options_from_fixture(self):
        html = (FIXTURES / "unit3d_upload_page.html").read_text(encoding="utf-8")
        self.assertEqual(extract_csrf_token(html), "csrf-token-123")
        self.assertEqual(extract_upload_form_action("https://unwalled.cc", html), "https://unwalled.cc/torrents")
        self.assertEqual(parse_select_options(html, "category_id"), {"11": "Comedy", "12": "Science"})
        self.assertEqual(parse_select_options(html, "type_id"), {"21": "Free Audio", "22": "Patreon Audio"})

    def test_parse_category_metadata_decodes_unit3d_cats_payload(self):
        html = """
        <div x-data="{ cats: JSON.parse(atob('eyIxMSI6eyJuYW1lIjoiQ29tZWR5IiwidHlwZSI6Im5vIn0sIjQyIjp7Im5hbWUiOiJUViIsInR5cGUiOiJ0diJ9fQ==')) }"></div>
        """
        self.assertEqual(
            parse_category_metadata(html),
            {
                "11": {"name": "Comedy", "type": "no"},
                "42": {"name": "TV", "type": "tv"},
            },
        )

    def test_extract_form_defaults_prefers_hidden_defaults_over_empty_text_inputs(self):
        html = """
        <form action="https://unwalled.cc/torrents">
          <input type="file" name="torrent" />
          <input type="hidden" name="_token" value="csrf-token-123" />
          <input type="hidden" name="stream" value="0" />
          <input type="checkbox" name="stream" />
          <input type="hidden" name="tmdb" value="0" />
          <input type="text" name="tmdb" value="" />
          <input type="hidden" name="anon" value="0" />
          <input type="checkbox" name="anon" value="1" />
        </form>
        """
        self.assertEqual(
            extract_form_defaults(html),
            {"_token": "csrf-token-123", "stream": "0", "tmdb": "0", "anon": "0"},
        )

    def test_extract_validation_errors_from_fixture(self):
        html = (FIXTURES / "unit3d_upload_error.html").read_text(encoding="utf-8")
        self.assertEqual(
            extract_validation_errors(html),
            ["Name has already been taken.", "Banner image is required."],
        )

    def test_extract_success_links_from_download_check_url(self):
        details_url, download_url = extract_success_links(
            "https://unwalled.cc",
            "https://unwalled.cc/download_check/321",
            "<html></html>",
        )
        self.assertEqual(details_url, "https://unwalled.cc/torrents/321")
        self.assertEqual(download_url, "https://unwalled.cc/torrents/download/321")

    def test_extract_success_links_prefers_download_link_in_html(self):
        details_url, download_url = extract_success_links(
            "https://unwalled.cc",
            "https://unwalled.cc/torrents/321",
            '<html><body><a href="/torrents/download/321">Download</a></body></html>',
        )
        self.assertEqual(details_url, "https://unwalled.cc/torrents/321")
        self.assertEqual(download_url, "https://unwalled.cc/torrents/download/321")

    def test_prepare_cover_image_outputs_square_jpeg(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            source = Path(temp_dir) / "cover.png"
            output = Path(temp_dir) / "cover-upload.jpg"
            Image.new("RGBA", (300, 500), color=(255, 0, 0, 255)).save(source)

            prepare_cover_image(source, output)

            self.assertTrue(output.exists())
            with Image.open(output) as image:
                self.assertEqual(image.format, "JPEG")
                self.assertEqual(image.size, (600, 600))

    def test_prepare_banner_image_outputs_jpeg_under_budget(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            source = Path(temp_dir) / "banner.png"
            output = Path(temp_dir) / "banner-upload.jpg"
            Image.new("RGB", (2200, 1400), color=(0, 120, 255)).save(source)

            prepare_banner_image(source, output, size_budget=120_000)

            self.assertTrue(output.exists())
            self.assertLessEqual(output.stat().st_size, 120_000)
            with Image.open(output) as image:
                self.assertEqual(image.format, "JPEG")
                self.assertGreaterEqual(image.size[0], 960)
                self.assertGreaterEqual(image.size[1], 540)
                self.assertAlmostEqual(image.size[0] / image.size[1], 16 / 9, places=2)

    def test_create_banner_from_cover_derives_valid_jpeg(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            source = Path(temp_dir) / "cover.png"
            output = Path(temp_dir) / "banner-upload.jpg"
            Image.new("RGB", (1500, 1500), color=(210, 30, 90)).save(source)

            create_banner_from_cover(source, output, size_budget=200_000)

            self.assertTrue(output.exists())
            self.assertLessEqual(output.stat().st_size, 200_000)
            with Image.open(output) as image:
                self.assertEqual(image.format, "JPEG")
                self.assertEqual(image.size, (1280, 720))

    def test_build_payload_uses_unwalled_web_field_names(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            podcast = SimpleNamespace(
                name="Wine About It",
                folder_path=Path(temp_dir),
                image=SimpleNamespace(
                    get_meta_file_path=lambda: Path(temp_dir) / "Metadata" / "Wine About It.jpg",
                    get_file_path=lambda: Path(temp_dir) / "Wine About It.image.jpg",
                ),
            )
            upload_context = SimpleNamespace(
                name="Wine About It [2024/MP3 - 320kbps]",
                raw_name="Wine About It [2024/MP3 - 320kbps]",
                description="description text",
                keywords_string="comedy, Patreon",
                data={"mediainfo": {"output": "Audio\nBit rate : 320 kb/s"}, "number_of_files": 12},
            )
            config = {
                "upload": {
                    "base_url": "https://unwalled.cc",
                    "cookie_file": "cookies.txt",
                    "ask": False,
                }
            }

            uploader = Unit3DWebUploader(podcast, config, upload_context, Path(temp_dir) / "test.torrent")
            try:
                uploader.release_profile = ReleaseProfile(
                    category_id="11",
                    category_name="Comedy",
                    category_kind="no",
                    type_id="22",
                    type_name="Patreon Audio",
                    anonymous=False,
                    personal_release=False,
                    ads_removed=False,
                )
                payload = uploader._build_payload(
                    "csrf-token-123",
                    form_defaults={"stream": "0", "sd": "0", "tmdb": "0", "mal": "0", "anon": "0"},
                )
            finally:
                uploader.cleanup()

            self.assertEqual(payload["_token"], "csrf-token-123")
            self.assertEqual(payload["name"], "Wine About It [2024/MP3 - 320kbps]")
            self.assertEqual(payload["category_id"], "11")
            self.assertEqual(payload["type_id"], "22")
            self.assertEqual(payload["description"], "description text")
            self.assertEqual(payload["keywords"], "comedy, Patreon")
            self.assertEqual(payload["anon"], "0")
            self.assertEqual(payload["personal_release"], "0")
            self.assertEqual(payload["stream"], "0")
            self.assertEqual(payload["sd"], "0")
            self.assertEqual(payload["tmdb"], "0")
            self.assertEqual(payload["mal"], "0")
            self.assertEqual(payload["tvdb"], "0")
            self.assertEqual(payload["igdb"], "0")
            self.assertNotIn("season_number", payload)
            self.assertNotIn("episode_number", payload)
            self.assertIn("320 kb/s", payload["mediainfo"])

    def test_build_payload_omits_mediainfo_when_disabled(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            podcast = SimpleNamespace(
                name="Wine About It",
                folder_path=Path(temp_dir),
                image=SimpleNamespace(
                    get_meta_file_path=lambda: Path(temp_dir) / "Metadata" / "Wine About It.jpg",
                    get_file_path=lambda: Path(temp_dir) / "Wine About It.image.jpg",
                ),
            )
            upload_context = SimpleNamespace(
                name="Wine About It [2024/M4A - 192kbps]",
                raw_name="Wine About It [2024/M4A - 192kbps]",
                description="description text",
                keywords_string="society, culture, Patreon",
                data={"mediainfo": {"output": "Audio\nBit rate : 192 kb/s"}, "number_of_files": 12},
            )
            config = {
                "upload": {
                    "base_url": "https://unwalled.cc",
                    "cookie_file": "cookies.txt",
                    "ask": False,
                    "include_mediainfo": False,
                }
            }

            uploader = Unit3DWebUploader(podcast, config, upload_context, Path(temp_dir) / "test.torrent")
            try:
                uploader.release_profile = ReleaseProfile(
                    category_id="11",
                    category_name="Comedy",
                    category_kind="no",
                    type_id="22",
                    type_name="Patreon Audio",
                    anonymous=False,
                    personal_release=False,
                    ads_removed=False,
                )
                payload = uploader._build_payload(
                    "csrf-token-123",
                    form_defaults={"stream": "0", "sd": "0", "tmdb": "0", "mal": "0", "anon": "0"},
                )
            finally:
                uploader.cleanup()

            self.assertEqual(payload["mediainfo"], "")

    def test_download_uploaded_torrent_replace_prompt_defaults_to_yes(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            podcast = SimpleNamespace(
                name="Wine About It",
                folder_path=Path(temp_dir),
                image=SimpleNamespace(
                    get_meta_file_path=lambda: Path(temp_dir) / "Metadata" / "Wine About It.jpg",
                    get_file_path=lambda: Path(temp_dir) / "Wine About It.image.jpg",
                ),
            )
            upload_context = SimpleNamespace(
                name="Wine About It [2024/M4A - 192kbps]",
                raw_name="Wine About It [2024/M4A - 192kbps]",
                description="description text",
                keywords_string="society, culture, Patreon",
                data={"mediainfo": {"output": ""}, "number_of_files": 12},
            )
            config = {
                "upload": {
                    "base_url": "https://unwalled.cc",
                    "cookie_file": "cookies.txt",
                    "ask": False,
                }
            }

            torrent_path = Path(temp_dir) / "test.torrent"
            torrent_path.write_bytes(b"torrent")
            uploader = Unit3DWebUploader(podcast, config, upload_context, torrent_path)
            tracker_torrent_path = uploader._build_tracker_torrent_path()
            tracker_torrent_path.write_bytes(b"old")
            response = Mock(ok=True, content=b"new")
            uploader.session.get = Mock(return_value=response)
            try:
                with patch("classes.uploaders.unit3d_web.ask_yes_no", return_value=False) as ask_yes_no:
                    returned_path = uploader._download_uploaded_torrent("https://unwalled.cc/torrents/download/1")
            finally:
                uploader.cleanup()

            self.assertEqual(returned_path, tracker_torrent_path)
            ask_yes_no.assert_called_once_with(
                f"Tracker torrent {tracker_torrent_path} already exists. Replace it?",
                default_yes=True,
            )

    def test_resolve_release_profile_uses_run_memory_as_prompt_defaults(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            podcast = SimpleNamespace(
                name="Wine About It",
                folder_path=Path(temp_dir),
                metadata=SimpleNamespace(get_tags=lambda: "", data={}, get_rss_feed=lambda: ""),
            )
            upload_context = SimpleNamespace(source_label=None, name="Wine About It", raw_name="Wine About It")
            config = {
                "upload": {
                    "base_url": "https://unwalled.cc",
                    "cookie_file": "cookies.txt",
                    "ask": True,
                },
                "_runtime": {
                    "upload_prompt_defaults": {
                        "category_id": "12",
                        "type_id": "22",
                        "anonymous": True,
                        "personal_release": True,
                        "ads_removed": True,
                        "extra_keywords": ["foo.bar", "baz"],
                    }
                },
            }

            uploader = Unit3DWebUploader(podcast, config, upload_context, Path(temp_dir) / "test.torrent")
            try:
                with patch("classes.uploaders.unit3d_web.choose_option", side_effect=lambda *args, **kwargs: kwargs["default"]) as choose_option, \
                    patch("classes.uploaders.unit3d_web.ask_yes_no_default", side_effect=lambda *args, **kwargs: kwargs["default"]) as ask_yes_no_default, \
                    patch("classes.uploaders.unit3d_web.take_input", return_value="foo.bar, baz"):
                    profile = uploader._resolve_release_profile(
                        {"11": "Comedy", "12": "Human Interest"},
                        {"21": "Audio - Free", "22": "Audio - Patreon"},
                        dry_run=False,
                    )
            finally:
                uploader.cleanup()

            self.assertEqual(profile.category_id, "12")
            self.assertEqual(profile.type_id, "22")
            self.assertTrue(profile.anonymous)
            self.assertTrue(profile.personal_release)
            self.assertTrue(profile.ads_removed)
            self.assertEqual(profile.extra_keywords, ["foo.bar", "baz"])
            self.assertEqual(choose_option.call_args_list[0].kwargs["default"], "12")
            self.assertEqual(choose_option.call_args_list[1].kwargs["default"], "22")
            self.assertEqual(ask_yes_no_default.call_args_list[0].kwargs["default"], True)
            self.assertEqual(ask_yes_no_default.call_args_list[1].kwargs["default"], True)
            self.assertEqual(ask_yes_no_default.call_args_list[2].kwargs["default"], True)

    def test_resolve_release_profile_persists_choices_for_later_years(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            podcast = SimpleNamespace(
                name="Wine About It",
                folder_path=Path(temp_dir),
                metadata=SimpleNamespace(get_tags=lambda: "", data={}, get_rss_feed=lambda: ""),
            )
            upload_context = SimpleNamespace(source_label=None, name="Wine About It", raw_name="Wine About It")
            config = {
                "upload": {
                    "base_url": "https://unwalled.cc",
                    "cookie_file": "cookies.txt",
                    "ask": True,
                },
                "_runtime": {},
            }

            uploader = Unit3DWebUploader(podcast, config, upload_context, Path(temp_dir) / "test.torrent")
            try:
                with patch("classes.uploaders.unit3d_web.choose_option", side_effect=["31", "7"]), \
                    patch("classes.uploaders.unit3d_web.ask_yes_no_default", side_effect=[False, False, True]), \
                    patch("classes.uploaders.unit3d_web.take_input", return_value="wine about it, qtcinderella"):
                    profile = uploader._resolve_release_profile(
                        {"6": "Comedy", "31": "Human Interest"},
                        {"7": "Audio - Patreon", "9": "Audio - Free"},
                        dry_run=False,
                    )
            finally:
                uploader.cleanup()

            self.assertEqual(profile.category_id, "31")
            self.assertEqual(profile.type_id, "7")
            self.assertEqual(
                config["_runtime"]["upload_prompt_defaults"],
                {
                    "category_id": "31",
                    "type_id": "7",
                    "anonymous": False,
                    "personal_release": False,
                    "ads_removed": True,
                    "extra_keywords": ["wine about it", "qtcinderella"],
                },
            )

    def test_resolve_release_profile_skips_prompts_when_split_auto_apply_is_active(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            podcast = SimpleNamespace(
                name="Wine About It",
                folder_path=Path(temp_dir),
                metadata=SimpleNamespace(get_tags=lambda: "", data={}, get_rss_feed=lambda: ""),
            )
            upload_context = SimpleNamespace(source_label=None, name="Wine About It", raw_name="Wine About It")
            config = {
                "upload": {
                    "base_url": "https://unwalled.cc",
                    "cookie_file": "cookies.txt",
                    "ask": True,
                },
                "_runtime": {
                    "split_auto_apply_remaining": True,
                    "upload_prompt_defaults": {
                        "category_id": "31",
                        "type_id": "7",
                        "anonymous": True,
                        "personal_release": False,
                        "ads_removed": False,
                        "extra_keywords": ["wine.about.it"],
                    },
                },
            }

            uploader = Unit3DWebUploader(podcast, config, upload_context, Path(temp_dir) / "test.torrent")
            try:
                with patch("classes.uploaders.unit3d_web.choose_option") as choose_option, patch(
                    "classes.uploaders.unit3d_web.ask_yes_no_default"
                ) as ask_yes_no_default, patch("classes.uploaders.unit3d_web.take_input") as take_input:
                    profile = uploader._resolve_release_profile(
                        {"6": "Comedy", "31": "Human Interest"},
                        {"7": "Audio - Patreon", "9": "Audio - Free"},
                        dry_run=False,
                    )
            finally:
                uploader.cleanup()

            choose_option.assert_not_called()
            ask_yes_no_default.assert_not_called()
            take_input.assert_not_called()
            self.assertEqual(profile.category_id, "31")
            self.assertEqual(profile.type_id, "7")
            self.assertTrue(profile.anonymous)
            self.assertEqual(profile.extra_keywords, ["wine.about.it"])


if __name__ == "__main__":
    unittest.main()
