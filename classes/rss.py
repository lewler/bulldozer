# rss.py
import requests
import re
import os
import shutil
import xml.etree.ElementTree as ET
from pathlib import Path
from titlecase import titlecase
from .utils import spinner, get_metadata_directory, log, find_case_insensitive_files
from .utils import special_capitalization, archive_metadata, ask_yes_no, announce

class Rss:
    def __init__(self, podcast, source_rss_file, config, censor_rss):
        """
        Initialize the Rss with the podcast, source RSS file, configuration, and censor RSS flag.

        :param podcast: The podcast object containing information about the podcast.
        :param source_rss_file: The source RSS file to download.
        :param config: The configuration settings.
        :param censor_rss: If True, the RSS feed will be censored.

        The Rss class is responsible for downloading and processing the RSS feed for the podcast.
        """
        self.podcast = podcast
        self.source_rss_file = source_rss_file
        self.config = config
        self.censor_rss = censor_rss
        self.keep_source_rss = self.config.get('keep_source_rss', False)
        self.archive = config.get('archive_metadata', False)
        self.metadata = dict()

    def default_file_path(self):
        """
        Get the default path to the RSS feed file.

        :return: The default path to the RSS feed file.
        """
        file_name = 'podcast.rss' if self.podcast.name == 'unknown podcast' else f'{self.podcast.name}.rss'
        return get_metadata_directory(self.podcast.folder_path, self.config) / file_name

    def get_file_path(self):
        """
        Get the path to the RSS feed file.
        
        :return: The path to the RSS feed file.
        """
        metadata_directory = get_metadata_directory(self.podcast.folder_path, self.config)
        if not metadata_directory.exists():
            return None
        if self.default_file_path().exists():
            return self.default_file_path()
        rss_file = find_case_insensitive_files('*.rss', get_metadata_directory(self.podcast.folder_path, self.config))
        if not rss_file:
            return None
        return rss_file[0]

    def extract_folder_name_from(self):
        """
        Extract the folder name from the RSS feed.

        :return: The folder name extracted from the RSS feed.
        """
        tree = ET.parse(self.get_file_path())
        root = tree.getroot()
        channel = root.find('channel')
        if channel is not None:
            title = channel.find('title')
            if title is not None:
                new_title = title.text.replace("_", " -").replace(":", " -").replace(" | Wondery+ Edition", "").replace(" | Wondery+", "")
                new_title = re.sub(r'[^\w\s-]', '', new_title)
                new_title = new_title.strip().strip('-')
                return titlecase(new_title, callback=lambda word, **kwargs: special_capitalization(word, self.config, None, **kwargs))
        return None 

    def get_episode_count_from(self):
        """
        Get the episode count from the RSS feed.

        :return: The episode count from the RSS feed.
        """
        tree = ET.parse(self.get_file_path())
        root = tree.getroot()
        channel = root.find('channel')
        if channel is not None:
            items = channel.findall('item')
            return len(items)
        return 0
    
    def rename(self):
        """
        Rename the RSS file to the podcast name.
        """
        old_file_path = get_metadata_directory(self.podcast.folder_path, self.config) / f'podcast.rss'
        new_file_path = get_metadata_directory(self.podcast.folder_path, self.config) / f'{self.podcast.name}.rss'
        log(f"Renaming RSS file from {old_file_path} to {new_file_path}", "debug")
        old_file_path.rename(new_file_path)

    def get_metadata(self):
        """
        Get the metadata from the RSS feed.

        :return: True if the metadata was successfully extracted, False otherwise.
        """
        if not self.get_file_path():
            self.get_file()

        if not self.get_file_path():
            log("RSS file could not be fetched", "error")
            return False

        with spinner("Getting metadata from feed") as spin:
            self.metadata['name'] = self.extract_folder_name_from()
            if not self.metadata['name']:
                spin.fail("✖")
                log("Failed to extract name from RSS feed", "critical")
                exit(1)

            new_folder_path = self.podcast.folder_path.parent / f'{self.metadata['name']}'
            if new_folder_path.exists():
                spin.fail("✖")
                log(f"Folder {new_folder_path} already exists", "critical")
                if not ask_yes_no("Folder already exists, do you want to overwrite it?"):
                    announce("Exiting, cya later!", "info")
                    exit(1)

                shutil.rmtree(new_folder_path)

            self.podcast.folder_path.rename(new_folder_path)
            log(f"Folder renamed to {new_folder_path}", "debug")
            self.podcast.folder_path = new_folder_path
            self.podcast.name = self.metadata['name']
            self.rename()
            self.metadata['total_episodes'] = self.get_episode_count_from()
            self.check_for_premium_show()
            spin.ok("✔")

        return True

    def download_file(self):
        """
        Download the RSS feed file.
        """
        with spinner("Downloading RSS feed") as spin:
            try:
                # Add headers to mimic a browser
                headers = {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
                    "Accept-Language": "en-US,en;q=0.9",
                    "Accept-Encoding": "gzip, deflate, br",
                    "Connection": "keep-alive"
                }
                response = requests.get(self.source_rss_file, headers=headers)
                response.raise_for_status()
                with self.default_file_path().open('wb') as rss_file:
                    rss_file.write(response.content)
                log(f"RSS feed downloaded to {self.default_file_path()}", "debug")
                spin.ok("✔")
            except requests.RequestException as e:
                spin.fail("✘")
                log(f"Failed to download RSS feed", "critical")
                log(e, "debug")
                raise
    
    def load_local_file(self):
        """
        Load the local RSS feed file.
        """
        if self.keep_source_rss:
            shutil.copy(self.source_rss_file, self.get_file_path())
        else:
            self.source_rss_file.rename(self.get_file_path())
            self.source_rss_file = None

    def get_file(self):
        """
        Get the RSS feed file.
        """
        if not self.source_rss_file:
            return False
        
        self.default_file_path().parent.mkdir(parents=True, exist_ok=True)

        if os.path.exists(self.source_rss_file):
            self.source_rss_file = Path(self.source_rss_file).resolve()
            self.load_local_file()
        else:
            self.download_file()
    
    def edit_rss_feed(self):
        """
        Edit the RSS feed file.
        """
        # find all strings matching the regex saved in config censor_rss_patterns, and replace them
        with self.get_file_path().open('r') as rss_file:
            rss_content = rss_file.read()
        if not rss_content:
            log("RSS file is empty, can't be edited", "warning")
            return
        for item in self.config.get('censor_rss_patterns', []):
            pattern = item['pattern']
            replacement = item['replacement']
            flags = item.get('flags', [])
            regex_flags = 0
            flag_mapping = {
                'IGNORECASE': re.IGNORECASE,
                'MULTILINE': re.MULTILINE,
                'DOTALL': re.DOTALL,
                'VERBOSE': re.VERBOSE,
                'ASCII': re.ASCII,
            }
            for flag in flags:
                regex_flags |= flag_mapping.get(flag.upper(), 0)

            repeat = item.get('repeat_until_no_change', False)

            if repeat:
                previous_content = None
                while previous_content != rss_content:
                    previous_content = rss_content
                    rss_content = re.sub(pattern, replacement, rss_content)
            else:
                rss_content = re.sub(pattern, replacement, rss_content)
        with self.get_file_path().open('w') as rss_file:
            rss_file.write(rss_content)

    def archive_file(self):
        """
        Delete the RSS feed file.
        """
        if not self.get_file_path():
            log("RSS file does not exist, can't be archived", "warning")
            return
        if self.archive:
            log(f"Archiving RSS feed {self.get_file_path().name}", "debug")
            archive_metadata(self.get_file_path(), self.config.get('archive_metadata_directory', None))
        if self.censor_rss:
            censor_mode = self.config.get('rss_censor_mode', 'delete')
            if censor_mode == 'edit':
                if self.get_file_path():
                    self.edit_rss_feed()
                    log(f"RSS feed edited since censor was true: {self.get_file_path()}", "debug")
            else:
                if self.get_file_path():
                    self.get_file_path().unlink()
                    log(f"RSS feed deleted since censor was true: {self.get_file_path()}", "debug")

    def check_for_premium_show(self):
        """
        Check if the podcast is a premium show.

        :return: A string indicating the premium status of the podcast.
        """
        if not self.get_file_path():
            log("RSS file does not exist, can't check for premium status", "warning")
            return ""
        tree = ET.parse(self.get_file_path())
        root = tree.getroot()
        channel = root.find('channel')
        if channel is not None:
            for network in self.config.get('premium_networks', []):
                if not network.get('tag') or not network.get('text') or not network.get('name'):
                    log(f"Invalid premium network configuration: {network}", "debug")
                    continue
                tag = channel.find(network['tag'])
                if tag is not None:
                    if network['text'] in tag.text:
                        log(f"Identified premium network {network['name']} from RSS feed", "debug")
                        self.censor_rss = True
                        if not self.config.get('include_premium_tag', True):
                            return ""
                        return f" ({network['name']})"
        return ""
    
    def get_episodes(self):
        """
        Parse the RSS feed to extract episode titles in chronological order.

        :param rss_feed_path: Path to the RSS feed XML file
        :return: List of episode titles in chronological order
        """
        if not self.get_file_path():
            log("RSS file does not exist, can't fix episode numbering", "warning")
            return []
        try:
            tree = ET.parse(self.get_file_path())
            root = tree.getroot()

            items = root.findall('./channel/item')

            episode_titles = []
            for item in items:
                title_element = item.find('title')
                if title_element is not None:
                    episode_titles.append(title_element.text)

            return episode_titles

        except ET.ParseError as e:
            log(f"Error parsing RSS feed", "error")
            log(e, "debug")
            return []

