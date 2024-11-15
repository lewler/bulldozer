# report.py
from collections import Counter
from pathlib import Path
from .utils import spinner, log, format_last_date, ask_yes_no, take_input
from .report_template import ReportTemplate

class Report:
    def __init__(self, podcast, config):
        """
        Initialize the Report with the podcast and configuration.

        :param podcast: The podcast object containing information about the podcast.
        :param config: The configuration

        The Report class is responsible for generating the report for the podcast.
        """
        self.podcast = podcast
        self.config = config

    def get_file_path(self, check_files_only=False):
        """
        Get the path to the report file in the base directory.

        :param check_files_only: If True, only check for files and do not generate the full report.
        :return: The path to the report file in the base directory.
        """
        base_dir = self.config.get('base_dir', None)
        if not base_dir:
            base_dir = self.podcast.folder_path.parent
        file_name = f'{self.podcast.name}.files.txt' if check_files_only else f'{self.podcast.name}.txt'
        return Path(base_dir) / file_name
    
    def check_if_report_exists(self):
        """
        Check if the report file already exists.

        :return: True if the report file already exists, False otherwise.
        """
        output_filename = self.get_file_path()
        return output_filename.exists()

    def generate(self, check_files_only=False):
        """
        Generate the report for the podcast.

        :param check_files_only: If True, only check for files and do not generate the full report.
        """
        template = ReportTemplate(self.podcast, self.config)
        cutoff = self.config.get('cutoff', .5)
        output_filename = self.get_file_path(check_files_only)

        with spinner("Generating report") as spin:
            bitrates_counter = Counter()
            for bitrate_str, files in self.podcast.analyzer.bitrates.items():
                bitrates_counter[bitrate_str] = len(files)

            total_files = sum(bitrates_counter.values())

            most_common_bitrate, most_common_count = bitrates_counter.most_common(1)[0]
            if most_common_count > total_files * cutoff:
                overall_bitrate = most_common_bitrate
            elif self.podcast.analyzer.all_vbr:
                overall_bitrate = "VBR"
            else:
                overall_bitrate = "Mixed"

            file_formats_counter = Counter()
            for file_format, files in self.podcast.analyzer.file_formats.items():
                file_formats_counter[file_format] = len(files)

            most_common_file_format, most_common_count = file_formats_counter.most_common(1)[0]
            if most_common_count > total_files * cutoff:
                file_format = most_common_file_format
            else:
                file_format = "Mixed"

            date_format_long = self.config.get('date_format_long', '%B %d %Y')
            start_year_str = str(self.podcast.analyzer.earliest_year) if self.podcast.analyzer.earliest_year else "Unknown"
            try:
                last_episode_date_str = format_last_date(self.podcast.analyzer.last_episode_date, date_format_long) if self.podcast.analyzer.last_episode_date else "Unknown"
            except ValueError as e:
                log(f"Error formatting last episode date", "error")
                log(e, "debug")
                spin.stop()
                last_episode_date = take_input(f"Can't use ({self.podcast.analyzer.last_episode_date}). Enter last episode date (YYYY-MM-DD)")
                if not last_episode_date:
                    log("No last episode date entered. Skipping report generation.", "debug")
                    spin.fail("✖")
                spin = spinner("Generating report")
                last_episode_date_str = format_last_date(last_episode_date, date_format_long)

            if self.podcast.completed:
                last_episode_date_str = last_episode_date_str.split()[2]
                if start_year_str == last_episode_date_str:
                    last_episode_date_str = ""

            if last_episode_date_str:
                last_episode_date_str = f"-{last_episode_date_str}"

            if file_format != "Mixed":
                file_format = file_format.upper()

            dynamic_data = {
                "start_year_str": start_year_str,
                "last_episode_date_str": last_episode_date_str,
                "file_format": file_format,
                "overall_bitrate": overall_bitrate,
            }
            data = {
                "file_format": file_format,
                "overall_bitrate": overall_bitrate,
                "number_of_files": total_files,
                "completed": self.podcast.completed,
                "average_duration": self.podcast.analyzer.get_average_duration(),
                "longest_duration": self.podcast.analyzer.get_longest_duration(),
                "shortest_duration": self.podcast.analyzer.get_shortest_duration(),
            }
            name = template.get_name(dynamic_data)
            if name:
                data['name'] = name

            data['name_clean'] = self.podcast.name

            if not check_files_only:
                tags = self.podcast.metadata.get_tags()
                if tags:
                    data['tags'] = tags

                description = self.podcast.metadata.get_description()
                if description:
                    data['description'] = description

                last_episode_included = None
                if not self.podcast.completed:
                    last_episode_included = self.podcast.analyzer.last_episode_date
                data['last_episode_included'] = last_episode_included

            bitrate_breakdown = ""
            if overall_bitrate == "Mixed" or check_files_only:
                sorted_bitrates = sorted(bitrates_counter.keys(), key=lambda b: float(b.replace(' kbps', '')) if 'kbps' in b else float('inf'))
                for bitrate in sorted_bitrates:
                    bitrate_breakdown += f"{bitrate}:\n"
                    for file in sorted(self.podcast.analyzer.bitrates[bitrate]):
                        bitrate_breakdown += f"  {file.name}\n"
            if bitrate_breakdown:
                data['bitrate_breakdown'] = bitrate_breakdown[:-1]

            differing_bitrates = ""
            if len(bitrates_counter) > 1 and not self.podcast.analyzer.all_vbr and overall_bitrate != "Mixed" and not check_files_only:
                for bitrate, files in self.podcast.analyzer.bitrates.items():
                    if bitrate != most_common_bitrate:
                        differing_bitrates += f"{bitrate}:\n"
                        for file in files:
                            differing_bitrates += f"  {file.name}\n"
            if differing_bitrates:
                data['differing_bitrates'] = differing_bitrates[:-1]

            file_format_breakdown = ""
            if file_format == "Mixed" or check_files_only:
                for format, count in file_formats_counter.items():
                    file_format_breakdown += f"{format.upper()}:\n"
                    for file in self.podcast.analyzer.file_formats[format]:
                        file_format_breakdown += f"  {file.name}\n"
            if file_format_breakdown:
                data['file_format_breakdown'] = file_format_breakdown[:-1]

            differing_file_formats = ""
            if len(file_formats_counter) > 1 and file_format != "Mixed" and not check_files_only:
                for format, files in self.podcast.analyzer.file_formats.items():
                    if format != most_common_file_format:
                        differing_file_formats += f"{format.upper()}:\n"
                        for file in files:
                            differing_file_formats += f"  {file.name}\n"
            if differing_file_formats:
                data['differing_file_formats'] = differing_file_formats[:-1]

            if not check_files_only:
                links = self.podcast.metadata.get_links()
                if links:
                    data['links'] = template.get_links(links)

                for site, external_data in self.podcast.metadata.external_data.items():
                    data[site] = external_data

            log(f"Data passed to the template: {data}", "debug")

            with open(output_filename, 'w') as f:
                log(f"Writing report to {output_filename}", "debug")
                f.write(template.render(data)[1:])
        spin.ok("✔")
