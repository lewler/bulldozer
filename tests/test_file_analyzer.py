import unittest

from classes.file_analyzer import extract_date_from_filename_text


class FilenameDateExtractionTest(unittest.TestCase):
    def test_extracts_iso_date_from_filename(self):
        self.assertEqual(
            extract_date_from_filename_text("2018-11-30 JIBO IS DEAD!!.mp3"),
            "2018-11-30",
        )

    def test_extracts_month_name_date_from_filename(self):
        self.assertEqual(
            extract_date_from_filename_text("APPLE CAN'T SELL iPHONES In CHINA - The WAN Show Dec 14 2018.mp3"),
            "2018-12-14",
        )

    def test_extracts_day_first_month_name_date_from_filename(self):
        self.assertEqual(
            extract_date_from_filename_text("The WAN Show 14 Dec 2018 APPLE CAN'T SELL iPHONES In CHINA.mp3"),
            "2018-12-14",
        )


if __name__ == "__main__":
    unittest.main()
