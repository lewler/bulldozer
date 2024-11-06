# podcast_metadata.py
import json
import re
from .utils import log, archive_metadata, open_file_case_insensitive
from .data_formatter import DataFormatter
from .apis.podchaser import Podchaser
from .apis.podcastindex import Podcastindex
from .scrapers.podnews import Podnews

class PodcastMetadata:
    def __init__(self, podcast, config):
        """
        Initialize the PodcastMetadata with the podcast and configuration.

        :param podcast: The podcast object containing information about the podcast.
        :param config: The configuration

        The PodcastMetadata class is responsible for handling the podcast metadata file.
        """
        self.podcast = podcast
        self.config = config
        self.data = None
        self.external_data = {}
        self.has_data = False
        self.archive = config.get('archive_metadata', False)

    def get_file_path(self):
        """
        Get the path to the metadata file.

        :return: The path to the metadata file.
        """
        return self.podcast.folder_path / f'{self.podcast.name}.meta.json'

    def load(self, search_term=None):
        """
        Load the metadata from the file, and fetch data from the apis.

        :param search_term: The search term to use for finding the podcast.
        :return: True if the metadata was loaded successfully, False if there was an error, None if the file does not exist.
        """
        self.fetch_additional_data(search_term)
        filename = f"{self.podcast.name}.meta.json"
        self.check_if_podcast_is_complete()
        try:
            with open_file_case_insensitive(filename, self.podcast.folder_path) as f:
                if not f:
                    return None
                self.data = json.load(f)
                self.has_data = True
        except json.JSONDecodeError:
            log(f"Invalid JSON in file '{filename}'.", "error")
            log(json.JSONDecodeError.msg, "debug")
            return False
        
        return True
    
    def check_if_podcast_is_complete(self):
        """
        Check if the podcast is complete based on the metadata.
        """
        if not self.external_data:
            self.podcast.completed = False

        if self.external_data.get('podchaser', {}).get('status', 'ACTIVE') != 'ACTIVE':
            self.podcast.completed = True
            return

        self.podcast.completed = False
        
    def format_data(self):
        """
        Format the metadata data using the DataFormatter.
        """
        formatter = DataFormatter(self.config)
        self.data = formatter.format_data(self.data)
        self.external_data = formatter.format_data(self.external_data)
        
    def fetch_additional_data(self, search_term=None):
        """
        Fetch additional metadata from APIs.
        """
        self.get_podchaser_data(search_term)
        self.get_podcastindex_data(search_term)
        self.get_podnews_data(search_term)
        self.format_data()

    def replace_description(self, description):
        """
        Replace parts of the description based on the configuration.

        :param description: The description to replace parts of.
        :return: The description with replacements made.
        """
        replacements = self.config.get('description_replacements', [])
        for replacement in replacements:
            pattern = replacement['pattern']
            repl = replacement['replace_with']
            escaped_pattern = re.escape(pattern)
            description = re.sub(escaped_pattern, repl, description)
        if description and description[0] == '\n':
            description = description[1:]
        if description and description[-1] == '\n':
            description = description[:-1]
        return description.strip()

    def get_description(self):
        """
        Get the description from the metadata.

        :return: The description from the metadata.
        """
        if not self.data:
            return None

        description = self.data.get('description')
        if not description:
            return None

        return self.replace_description(description)

    def get_links(self):
        """
        Get the links from the metadata.

        :return: The links from the metadata.
        """
        if not self.data:
            return None

        links = {}
        if 'link' in self.data:
            links['Official Website'] = self.data['link'].strip()
        links['Podnews'] = 'https://podnews.net/podcast/123'
        links['Podcastindex.org'] = 'https://podcastindex.org/podcast/123'

        return links

    def get_tags(self):
        """
        Get the tags from the metadata.

        :return: The tags from the metadata.
        """
        if not self.data:
            return None
        
        if 'itunes' not in self.data or 'categories' not in self.data['itunes']:
            return
        
        categories = self.data['itunes']['categories']

        processed_categories = []
        for category in categories:
            parts = category.lower().split('&')
            processed_categories.extend([part.strip() for part in parts])

        if 'explicit' in self.data['itunes']:
            if self.data['itunes']['explicit'] == 'yes':
                processed_categories.append('explicit')

        return ', '.join(processed_categories)

    def get_rss_feed(self):
        """
        Get the RSS feed URL from the metadata.

        :return: The RSS feed URL from the metadata.
        """
        if not self.data:
            return None
        
        return self.data['feedUrl']
    
    def get_external_data(self, api_name, api_class, search_term, *args):
        """
        Get the data for the podcast from a specified API.
        
        :param api_name: Name of the API (e.g., 'podchaser', 'podcastindex').
        :param api_class: The class for interacting with the API (e.g., Podchaser, Podcastindex).
        :param search_term: The search term to use for finding the podcast.
        :param args: Additional arguments required for the API class constructor.
        """
        api_config = self.config.get(api_name, {})
        
        if not api_config.get('active', False):
            log(f"{api_name.capitalize()} API is not enabled.", "debug")
            return None
        
        if not search_term:
            search_term = self.podcast.name

        api_instance = api_class(*args)
        podcast = api_instance.find_podcast(search_term)
        
        if not podcast:
            self.external_data[api_name] = {}
            return False
        
        self.external_data[api_name] = podcast
        self.has_data = True
        return True
    
    def get_podchaser_data(self, search_term=None):
        """
        Get the Podchaser data for the podcast.

        :param search_term: The search term to use for finding the podcast.
        """
        return self.get_external_data(
            'podchaser',
            Podchaser,
            search_term,
            self.config.get('podchaser', {}).get('token', None),
            self.config.get('podchaser', {}).get('fields', None),
            self.config.get('podchaser', {}).get('url', None)
        )
    
    def get_podcastindex_data(self, search_term=None):
        """
        Get the Podcastindex data for the podcast.

        :param search_term: The search term to use for finding the podcast.
        """
        return self.get_external_data(
            'podcastindex',
            Podcastindex,
            search_term,
            self.config.get('podcastindex', {}).get('key', None),
            self.config.get('podcastindex', {}).get('secret', None),
            self.config.get('podcastindex', {}).get('url', None)
        )
    
    def get_podnews_data(self, search_term=None):
        """
        Get the Podnews data for the podcast.

        :param search_term: The search term to use for finding the podcast.
        """
        return self.get_external_data(
            'podnews',
            Podnews,
            search_term,
            self.config.get('podnews', {}).get('url', None)
        )
    
    def archive_file(self):
        """
        Archive the metadata file.

        If the archive_metadata configuration is set to True, the metadata file will be archived instead of deleted.
        """
        if not self.get_file_path().exists():
            return
        
        if not self.archive:
            log(f"Deleting meta {self.get_file_path().name}", "debug")
            self.get_file_path().unlink()
            return

        archive_folder = self.config.get('archive_metadata_directory', None)
        log(f"Archiving meta {self.get_file_path().name}", "debug")
        archive_metadata(self.get_file_path(), archive_folder)
        log(f"Deleting meta {self.get_file_path().name}", "debug")
        self.get_file_path().unlink()
