import unittest

from classes.upload_context import build_upload_keywords, sanitize_upload_title


class UploadContextHelpersTest(unittest.TestCase):
    def test_sanitize_upload_title_reformats_unwalled_title(self):
        title = "Wine & About It (Patreon) [2024/MP3-320 kbps]"
        self.assertEqual(
            sanitize_upload_title(title, "Patreon"),
            "Wine and About It [2024/MP3 - 320kbps]",
        )

    def test_build_upload_keywords_normalizes_multiword_terms_and_ads_removed(self):
        keywords = build_upload_keywords(
            config={"upload": {"keywords": ["Jack Black"], "ads_removed": True}},
            tags="comedy, society and culture",
            source_label="Patreon",
        )
        self.assertEqual(
            keywords,
            ["comedy", "society.and.culture", "Jack.Black", "Patreon", "ads.removed"],
        )


if __name__ == "__main__":
    unittest.main()
