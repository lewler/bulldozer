from pathlib import Path

from .utils import spinner, log
from .upload_context import UploadContextBuilder

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
        file_name = f'{self.podcast.folder_path.name}.files.txt' if check_files_only else f'{self.podcast.folder_path.name}.txt'
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
        output_filename = self.get_file_path(check_files_only)

        with spinner("Generating report") as spin:
            context = UploadContextBuilder(self.podcast, self.config).build(check_files_only)
            with open(output_filename, 'w') as f:
                log(f"Writing report to {output_filename}", "debug")
                f.write(context.description)
        spin.ok("✔")
