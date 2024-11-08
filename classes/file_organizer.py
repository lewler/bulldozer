# file_organizer.py
import fnmatch
import re
from datetime import datetime, timedelta
from pathlib import Path
from .utils import spinner, titlecase_filename, announce, log
from .utils import format_last_date, ask_yes_no, take_input, normalize_string

class FileOrganizer:
    def __init__(self, podcast, config):
        """
        Initialize the FileOrganizer with the podcast and configuration.
        
        :param podcast: The podcast object containing information about the podcast.
        :param config: The configuration settings.

        The FileOrganizer class is responsible for organizing the episode files in the podcast folder.
        """
        self.podcast = podcast
        self.config = config
        self.unwanted_files = self.config.get('unwanted_files', [])

    def rename_files(self):
        """
        Rename the episode files in the podcast folder.
        """
        ep_nr_at_end_file_pattern = re.compile(self.config.get('ep_nr_at_end_file_pattern', r'^(.* - )(\d{4}-\d{2}-\d{2}) (.*?)( - )(\d+)\.mp3$'))
        for file_path in Path(self.podcast.folder_path).rglob('*'):
            if file_path.is_file():
                self.rename_file(file_path, ep_nr_at_end_file_pattern)

    def get_new_name(self, name, file_path):
        """
        Get the new name for the file by applying the file replacements.

        :param name: The original name of the file.
        :param file_path: The path to the file.
        :return: The new name of the file.
        """
        for item in self.config.get('file_replacements', []):
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
                previous_name = None
                while previous_name != name:
                    previous_name = name
                    name = re.sub(pattern, replacement, name)
            else:
                name = re.sub(pattern, replacement, name)

        log(f"Renaming '{file_path.name}' to '{name}'", "debug")

        return file_path.with_name(name)
    
    def fix_episode_numbering(self, file_path, ep_nr_at_end_file_pattern):
        """
        Fix the episode numbering in the file name.

        :param file_path: The path to the file.
        :param ep_nr_at_end_file_pattern: The pattern to match episode numbers at the end of the file name.
        """
        match = ep_nr_at_end_file_pattern.match(file_path.name)
        if match:
            prefix = match.group(1)
            date_part = match.group(2)
            title = match.group(3).rstrip(' -').strip()
            last_number = match.group(5)
            extension = match.group(6)
            
            new_filename = f"{prefix}{date_part} {last_number}. {title}{extension}"
            new_path = file_path.with_name(new_filename)
            file_path.rename(new_path)
            file_path = new_path

        return file_path

    def rename_file(self, file_path, ep_nr_at_end_file_pattern):
        """
        Rename an individual episode file.

        :param file_path: The path to the file.
        :param ep_nr_at_end_file_pattern: The pattern to match episode numbers at the end of the file name.
        """
        new_name = titlecase_filename(file_path, self.config)

        new_path = self.get_new_name(new_name, file_path)
        file_path.rename(new_path)
        file_path = new_path

        self.fix_episode_numbering(file_path, ep_nr_at_end_file_pattern)

    def find_unwanted_files(self):
        """
        Find and remove unwanted files from the podcast folder.
        """
        announce("Checking if there are episodes we don't want", "info")
        for file_path in Path(self.podcast.folder_path).rglob('*'):
            if file_path.is_file() and any(unwanted_file.lower() in file_path.name.lower() for unwanted_file in self.unwanted_files):
                if ask_yes_no(f"Would you like to remove '{file_path.name}'"):
                    file_path.unlink()

    def pad_episode_numbers(self):
        """
        Pad episode numbers with zeros to make them consistent
        """
        pattern = re.compile(self.config.get('episode_pattern', r'(Ep\.?|Episode|E)\s*(\d+)'), re.IGNORECASE)

        files_with_episodes = []

        for filename in Path(self.podcast.folder_path).rglob('*'):
            match = pattern.search(filename.name)
            if match:
                episode_number = int(match.group(2))
                files_with_episodes.append((filename, episode_number))

        if not files_with_episodes:
            log("No files with episode numbers found", "debug")
            return

        max_episode_number = max(ep_num for _, ep_num in files_with_episodes)
        num_digits = len(str(max_episode_number))

        def pad_episode_number(match):
            prefix = match.group(1)
            episode_number = int(match.group(2))
            padded_episode = str(episode_number).zfill(num_digits)
            return f"{prefix}{padded_episode}"

        for filename, _ in files_with_episodes:
            new_filename = pattern.sub(pad_episode_number, filename.name)
            new_path = filename.with_name(new_filename)

            filename.rename(new_path)
            log(f"Renamed '{filename}' to '{new_path}'", "debug")

    def find_files_without_episode_numbers(self):
        """
        Find files that share the same date but have no episode number.
        """
        date_pattern = re.compile(self.config.get('date_pattern', r'\b(\d{4}-\d{2}-\d{2})\b'))
        episode_pattern = re.compile(self.config.get('episode_pattern', r'(Ep\.?|Episode)\s*(\d+)'), re.IGNORECASE)

        files_by_date = {}

        for filename in Path(self.podcast.folder_path).rglob('*'):
            date_match = date_pattern.search(filename.name)
            if date_match:
                date = date_match.group(1)

                if date not in files_by_date:
                    files_by_date[date] = []

                files_by_date[date].append(filename)

        log(f"Files by date: {files_by_date}", "debug")

        files_without_episode_numbers = {}
        for date, files in files_by_date.items():
            if len(files) == 1:
                continue
            files_missing_episode = [
                file for file in files if not episode_pattern.search(file.name)
            ]
            if files_missing_episode:
                files_without_episode_numbers[date] = files_missing_episode

        log(f"Files without episode numbers: {files_without_episode_numbers}", "debug")

        return files_without_episode_numbers
    
    def assign_episode_numbers_from_rss(self, files_without_episode_numbers):
        """
        Assign episode numbers based on RSS feed order.
        """
        episode_titles = self.podcast.rss.get_episodes()
        episode_titles.reverse()
        filename_format = self.config.get('conflicing_dates_replacement', '{prefix} - {date} Ep. {episode} - {suffix}')

        for date, files in files_without_episode_numbers.items():
            max_episode_number = len(episode_titles)
            num_digits = len(str(max_episode_number))

            for index, file in enumerate(files):
                normalized_filename = normalize_string(file.name)
                for episode_number, title in enumerate(episode_titles, start=1):
                    normalized_title = normalize_string(title)
                    if normalized_title in normalized_filename:
                        padded_episode = str(episode_number).zfill(num_digits)

                        original_title = re.sub(rf'\b{date}\b ', '', file.name).strip()
                        title_parts = original_title.split(' - ', 1)
                        
                        new_filename = filename_format.format(prefix=title_parts[0], date=date, episode=padded_episode, suffix=title_parts[1])
                        new_path = file.with_name(new_filename)

                        file.rename(new_path)
                        log(f"Renamed '{file}' to '{new_path}'", "debug")
                        break

    def check_numbering(self):
        """
        Check if episode numbers are present and consistent in the file names.
        """
        announce("Checking if episode numbers are present and consistent", "info")
        self.pad_episode_numbers()
        conflicting_episodes = self.find_files_without_episode_numbers()
        if conflicting_episodes:
            self.assign_episode_numbers_from_rss(conflicting_episodes)
        pattern = re.compile(self.config.get('numbered_episode_pattern', r'^(.* - )(\d{4}-\d{2}-\d{2}) (\d+)\. (.*)(\.\w+)'))
    
        files = Path(self.podcast.folder_path).rglob('*')
        has_episode_number = any(pattern.match(f.name) for f in files)
        if has_episode_number:
            missing_episode_number = [f for f in files if not pattern.match(f.name)]
            if missing_episode_number:
                for f in missing_episode_number:
                    if (f.is_file() and not fnmatch.fnmatch(f.name, '*.mp3') and not fnmatch.fnmatch(f.name, '*.m4a')) or not f.is_file():
                        continue
                    episode_number = take_input(f"Episode number for '{f}' (blank skips)")
                    if episode_number:
                        original_pattern = re.compile(self.config.get('numbered_episode_pattern', r'^(.*) - (\d{4}-\d{2}-\d{2}) (.*?)(\.\w+)'))
                        match = original_pattern.match(f.name)
                        
                        if match:
                            prefix = match.group(1)
                            date_part = match.group(2)
                            title = match.group(3).strip()
                            extension = match.group(4)

                            new_filename = f"{prefix} - {date_part} {episode_number}. {title}{extension}"

                            folder_path = Path(folder_path)

                            old_filepath = folder_path / f
                            new_filepath = folder_path / new_filename

                            old_filepath.rename(new_filepath)

    def organize_files(self):
        """
        Organize the episode files in the podcast folder.
        """
        self.rename_folder()
        with spinner("Organizing episode files") as spin:
            self.rename_files()
            spin.ok("✔")

        self.find_unwanted_files()
        self.check_numbering()

    def rename_folder(self):
        """
        Rename the podcast folder based on the podcast name and last episode date.
        """
        if '(' in self.podcast.folder_path.name:
            return
        date_format_short = self.config.get('date_format_short', '%Y-%m-%d')
        date_format_long = self.config.get('date_format_long', '%B %d %Y')
        start_year_str = str(self.podcast.analyzer.earliest_year) if self.podcast.analyzer.earliest_year else "Unknown"
        last_episode_date_str = format_last_date(self.podcast.analyzer.last_episode_date, date_format_long) if self.podcast.analyzer.last_episode_date else "Unknown"
        last_episode_date_dt = datetime.strptime(self.podcast.analyzer.last_episode_date, date_format_short) if self.podcast.analyzer.last_episode_date != "Unknown" else None
        new_folder_name = None
        if last_episode_date_dt and datetime.now() - last_episode_date_dt > timedelta(days=self.config.get('completed_threshold_days', 365)):
            if ask_yes_no(f'Would you like to rename the folder to {self.podcast.name} (Complete)'):
                new_folder_name = f"{self.podcast.name} (Complete)"
                self.podcast.completed = True
        if not new_folder_name:
            if ask_yes_no(f'Would you like to rename the folder to {self.podcast.name} ({start_year_str}-{last_episode_date_str})'):
                new_folder_name = f"{self.podcast.name} ({start_year_str}-{last_episode_date_str})"
        if not new_folder_name:
            new_folder_name = take_input(f'Enter a custom name for the folder (blank skips)')

        if new_folder_name:
            new_folder_path = self.podcast.folder_path.parent / new_folder_name
            log(f"Renaming folder {self.podcast.folder_path} to {new_folder_path}", "debug")
            self.podcast.folder_path.rename(new_folder_path)
            self.podcast.folder_path = new_folder_path
        
        return
