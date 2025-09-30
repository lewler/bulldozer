# podcast.py
import re
import shutil
import hashlib
from .file_organizer import FileOrganizer
from .file_analyzer import FileAnalyzer
from .dupe_checker import DupeChecker
from .rss import Rss
from .podcast_image import PodcastImage
from .podcast_metadata import PodcastMetadata
from .utils import log, run_command, announce, spinner, get_metadata_directory, convert_paths_to_strings
from .database import Database

class Podcast:
    def __init__(self, name, folder_path, config, source_rss_file=None, censor_rss=False, check_duplicates=True, search_term=None, match_titles=None, after_date=None, before_date=None, latest_episode_only=False):
        """
        Initialize the Podcast with the name, folder path, configuration, and source RSS file.

        :param name: The name of the podcast.
        :param folder_path: The path to the podcast folder.
        :param config: The configuration settings.
        :param source_rss_file: The source RSS file to download.
        :param censor_rss: If True, the RSS feed will be censored.
        :param check_duplicates: If True, check for duplicate episodes.
        :param search_term: The search term used to find the podcast.
        :param match_titles: The titles to match when checking for duplicates.

        The Podcast class is responsible for handling the podcast.
        """
        self.name = name.replace(' --CURRENT--', '')
        if '(' in self.name:
            self.name = self.name.split('(')[0].strip()
        self.folder_path = folder_path
        self.config = config
        self.completed = False
        self.downloaded = False
        if not source_rss_file:
            self.downloaded = True
        self.search_term = search_term
        self.match_titles = match_titles
        self.after_date = after_date
        self.before_date = before_date
        self.latest_episode_only = latest_episode_only
        self.rss = Rss(self, source_rss_file, self.config, censor_rss)
        self.image = PodcastImage(self, self.config)
        self.metadata = PodcastMetadata(self, self.config)
        self.analyzer = FileAnalyzer(self, config)
        self.db = Database(config.get('database', {}).get('file', './podcasts.db'))
        if self.name != 'unknown podcast' and check_duplicates:
            self.check_for_duplicates()

    def get_metadata(self, critical=True):
        """
        Get the podcast metadata.

        :return: The podcast metadata.
        """
        metadata = self.rss.get_metadata_rename_folder()

        if not metadata and critical:
            announce("Failed to get metadata from RSS feed, make sure the feed validates", "critical")
            exit(1)
        elif not metadata:
            return metadata

        if self.name == 'unknown podcast':
            self.name = self.rss.metadata['name']

    def download_episodes(self, threads_override=None):
        """
        Download the podcast episodes using podcast-dl.
        """
        self.get_metadata()
        self.check_for_duplicates()

        episode_template = self.config.get("podcast_dl", {}).get('episode_template', "{{podcast_title}} - {{release_year}}-{{release_month}}-{{release_day}} {{title}}")
        threads = threads_override if threads_override is not None else self.config.get("podcast_dl", {}).get("threads", 1)

        command = (
            f'podcast-dl --file "{self.rss.get_file_path()}" --out-dir "{self.folder_path}" '
            f'--episode-template "{episode_template}" '
            f'--include-meta --threads {threads} --add-mp3-metadata'
        )
        download_output, return_code = run_command(command, progress_description="Downloading podcast episodes", track_progress=True, total_episodes=self.rss.metadata['total_episodes'])
        if return_code != 0:
            log("Failed to download episodes using podcast-dl.", "error")
            log(download_output, "debug")
            exit(1)

    def organize_files(self):
        """
        Organize the podcast files.
        """
        organizer = FileOrganizer(self, self.config)
        organizer.organize_files()

    def analyze_files(self):
        """
        Analyze the podcast files.
        """
        self.analyzer.analyze_files()

    def check_for_duplicates(self):
        """
        Check for duplicate episodes.

        :return: True if there are no duplicates, False otherwise.
        """
        if self.config.get('api_key') and self.config.get('dupecheck_url'):
            term = self.search_term if self.search_term else self.name
            dupe_checker = DupeChecker(term, self.config.get('dupecheck_url'), self.config.get('api_key'))
            progress = dupe_checker.check_duplicates()
            if not progress:
                self.cleanup_and_exit()
        else:
            log("Skipping duplicate check because 'api_key' or 'dupecheck_url' is not set in the config.", "debug")

    def archive_files(self):
        """
        Archive the podcast files.
        """
        with spinner("Organizing metadata files") as spin:
            self.metadata.archive_file()
            self.image.archive_file()
            self.rss.archive_file()
            if not self.config.get('include_metadata', False):
                metadata_directory = get_metadata_directory(self.folder_path, self.config)
                if metadata_directory.exists():
                    shutil.rmtree(metadata_directory)
            spin.ok("✔")

    def cleanup_and_exit(self):
        """
        Clean up and exit.
        """
        log("Cleaning up and exiting...", "debug")
        shutil.rmtree(self.folder_path)
        exit(1)

    def load_from_database(self, refresh=False):
        """
        Load the podcast data from the database.

        :param refresh: If True, refresh the podcast data.
        """
        hash = self.get_hash()
        podcast_data = self.db.get_podcast(hash)

        if not podcast_data:
            log(f"Podcast {self.name} not found in the database.", "debug")
            return

        self.analyzer.file_dates = podcast_data['files']
        if not refresh:
            self.metadata.data = podcast_data['metadata'] if 'metadata' in podcast_data else {}
            self.metadata.external_data = podcast_data['external_data'] if 'external_data' in podcast_data else {}
            self.metadata.has_data = True if self.metadata.data or self.metadata.external_data else False
            log(f"Podcast {self.name} loaded from the database.", "debug")

    def add_to_database(self, refresh=False):
        """
        Add this podcast to the database.

        :param refresh: If True, refresh the podcast data.
        """
        hash = self.get_hash()

        if refresh:
            log(f"Refresh is true, deleting podcast {self.name} from the database.", "debug")
            self.db.delete_podcast(hash)
        
        files = convert_paths_to_strings(self.analyzer.file_dates)
        self.db.insert_podcast(hash, files)
        log(f"Podcast {self.name} added to the database.", "debug")

    def add_metadata_to_database(self):
        """
        Add this podcast to the database.

        :param refresh: If True, refresh the podcast data.
        """
        hash = self.get_hash()
        metadata = self.metadata.data
        external_data = self.metadata.external_data
        self.db.update_podcast(hash, metadata=metadata, external_data=external_data)
        log(f"Podcast {self.name} added to the database.", "debug")

    def get_clean_name(self):
        """
        Get the clean name of the podcast.

        :return: The clean name of the podcast.
        """
        match = re.search(self.config.get('clean_name', r'^(.*?)(?=\()'), self.name)

        if not match:
            return self.name
        return match.group(1).strip()

    def get_hash(self):
        """
        Get the hash of the podcast.

        :return: The hash of the podcast.
        """
        return hashlib.md5(self.get_clean_name().encode('utf-8')).hexdigest()
