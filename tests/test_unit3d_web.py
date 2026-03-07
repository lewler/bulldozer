import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from PIL import Image

from classes.upload_context import ReleaseProfile
from classes.uploaders.unit3d_web import (
    create_banner_from_cover,
    extract_csrf_token,
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
                data={"mediainfo": {"output": "Audio\nBit rate : 320 kb/s"}},
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
                    type_id="22",
                    type_name="Patreon Audio",
                    anonymous=False,
                    personal_release=False,
                    ads_removed=False,
                )
                payload = uploader._build_payload("csrf-token-123")
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
            self.assertIn("320 kb/s", payload["mediainfo"])


if __name__ == "__main__":
    unittest.main()
