import unittest

from classes.report_template import extract_tracker_description


class ReportTemplateHelpersTest(unittest.TestCase):
    def test_extract_tracker_description_uses_marked_section(self):
        rendered = """
Name: Wine About It [M4A - 192kbps]
Tags: society, culture, explicit

--- Torrent Description ---
[b]Official Description[/b]
[quote]A podcast about nothing[/quote]
--- Torrent Description ---
        """.strip()

        self.assertEqual(
            extract_tracker_description(rendered),
            "[b]Official Description[/b]\n[quote]A podcast about nothing[/quote]",
        )

    def test_extract_tracker_description_falls_back_to_full_render(self):
        rendered = "[b]Simple description[/b]"
        self.assertEqual(extract_tracker_description(rendered), rendered)


if __name__ == "__main__":
    unittest.main()
