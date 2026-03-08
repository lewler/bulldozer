import unittest
from pathlib import Path

from jinja2 import Template

from classes.upload_context import (
    build_title_period_label,
    build_upload_keywords,
    sanitize_public_source_url,
    sanitize_upload_title,
)


class UploadContextHelpersTest(unittest.TestCase):
    def test_sanitize_upload_title_reformats_unwalled_title(self):
        title = "Wine & About It (Patreon) [2024/MP3-320 kbps]"
        self.assertEqual(
            sanitize_upload_title(title, "Patreon"),
            "Wine and About It [2024/MP3 - 320kbps]",
        )

    def test_build_upload_keywords_normalizes_multiword_terms_and_ads_removed(self):
        keywords = build_upload_keywords(
            tags="comedy, society and culture",
            source_label="Patreon",
            extra_keywords=["Jack Black"],
            ads_removed=True,
        )
        self.assertEqual(
            keywords,
            ["comedy", "society.and.culture", "Jack.Black", "Patreon", "ads.removed"],
        )

    def test_sanitize_public_source_url_removes_private_patreon_rss_auth(self):
        self.assertEqual(
            sanitize_public_source_url("https://www.patreon.com/rss/wineaboutit?auth=secret&show=870432"),
            "https://www.patreon.com/wineaboutit",
        )

    def test_build_title_period_label_uses_year_for_full_single_year_pack(self):
        self.assertEqual(
            build_title_period_label(
                start_year_str="2024",
                end_year_str="2024",
                first_episode_date="2024-01-02",
                last_episode_date="2024-12-25",
                completed=False,
                current_year=2026,
            ),
            "2024",
        )

    def test_build_title_period_label_uses_month_range_for_current_incomplete_year(self):
        self.assertEqual(
            build_title_period_label(
                start_year_str="2026",
                end_year_str="2026",
                first_episode_date="2026-01-07",
                last_episode_date="2026-03-04",
                completed=False,
                current_year=2026,
            ),
            "January 2026 - March 2026",
        )

    def test_build_title_period_label_uses_year_span_for_multi_year_pack(self):
        self.assertEqual(
            build_title_period_label(
                start_year_str="2023",
                end_year_str="2024",
                first_episode_date="2023-04-01",
                last_episode_date="2024-06-01",
                completed=False,
                current_year=2026,
            ),
            "2023-2024",
        )

    def test_name_unwalled_template_includes_year_for_split_packs(self):
        template_path = Path(__file__).resolve().parent.parent / "templates" / "name-unwalled.tpl"
        template = Template(template_path.read_text())
        rendered = template.render(
            name_clean="Wine About It",
            title_period_label="2024",
            start_year_str="2024",
            end_year_str="2024",
            file_format="M4A",
            overall_bitrate="192kbps",
        )
        self.assertEqual(rendered, "Wine About It [2024/M4A - 192kbps]")


if __name__ == "__main__":
    unittest.main()
