# file_organizer.py
import fnmatch
import mutagen
import re
from datetime import datetime, timedelta
from pathlib import Path
from mutagen.easyid3 import EasyID3
from mutagen.mp4 import MP4
from .utils import spinner, titlecase_filename, announce, log, perform_replacements
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
        ep_nr_at_end_file_pattern = re.compile(self.config.get('ep_nr_at_end_file_pattern', r'^(.* - )(\d{4}-\d{2}-\d{2}) (.*?)( - )((Ep\.?|Episode|E)?\s*(\d+))(\.\w+)$'))
        for file_path in Path(self.podcast.folder_path).rglob('*'):
            if file_path.is_file():
                new_file_path = self.rename_file(file_path, ep_nr_at_end_file_pattern)
                if new_file_path != file_path:
                    self.podcast.analyzer.update_file_path(file_path, new_file_path)

    def get_new_name(self, name, file_path):
        """
        Get the new name for the file by applying the file replacements.

        :param name: The original name of the file.
        :param file_path: The path to the file.
        :return: The new name of the file.
        """
        new_name = perform_replacements(name, self.config.get('file_replacements', []))
        if new_name != name:
            log(f"Renaming '{file_path.name}' to '{new_name}'", "debug")

        return file_path.with_name(new_name)
    
    def fix_episode_numbering(self, file_path, ep_nr_at_end_file_pattern):
        """
        Fix the episode numbering in the file name.

        :param file_path: The path to the file.
        :param ep_nr_at_end_file_pattern: The compiled pattern to match episode numbers at the end of the file name.
        """
        match = ep_nr_at_end_file_pattern.match(file_path.name)
        if match:
            prefix = match.group(1)
            date_part = match.group(2)
            title = match.group(3).rstrip(' -').strip()
            episode_number = match.group(5)
            extension = match.group(8)
            new_filename = f"{prefix}{date_part} {episode_number} - {title}{extension}"
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

        return self.fix_episode_numbering(file_path, ep_nr_at_end_file_pattern)

    def update_file_metadata(self):
        """
        Update metadata fields in audio files based on the 'file_metadata_replacements' configuration.
        """
        replacements = self.config.get('file_metadata_replacements', [])

        for file_path in Path(self.podcast.folder_path).rglob('*'):
            if file_path.suffix.lower() in ['.mp3', '.m4a']:
                try:
                    if file_path.suffix.lower() == '.mp3':
                        audio = EasyID3(file_path)
                    elif file_path.suffix.lower() == '.m4a':
                        audio = MP4(file_path)
                    else:
                        continue  # Skip unsupported formats

                    metadata_changed = False

                    for replacement in replacements:
                        fields = replacement.get('fields', [])
                        pattern = replacement.get('pattern', None)
                        repl = replacement.get('replacement', '')
                        flags = replacement.get('flags', [])
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

                        for field in fields:
                            # Handle MP3 files
                            if file_path.suffix.lower() == '.mp3':
                                if field in audio:
                                    original_value = audio[field][0]
                                    new_value = re.sub(pattern, repl, original_value, flags=regex_flags).strip()
                                    if new_value != original_value:
                                        audio[field] = new_value
                                        metadata_changed = True
                                        log(f"Updated '{field}' metadata in '{file_path.name}' from '{original_value}' to '{new_value}'", "debug")
                            # Handle M4A files
                            elif file_path.suffix.lower() == '.m4a':
                                tag_map = {
                                    'title': '\xa9nam',
                                    'artist': '\xa9ART',
                                    'album': '\xa9alb',
                                    'genre': '\xa9gen',
                                    'date': '\xa9day',
                                    'comment': '\xa9cmt',
                                    'composer': '\xa9wrt',
                                    'albumartist': 'aART',
                                }
                                mp4_field = tag_map.get(field.lower())
                                if mp4_field and mp4_field in audio.tags:
                                    original_value = audio.tags[mp4_field][0]
                                    new_value = re.sub(pattern, repl, original_value, flags=regex_flags).strip()
                                    if new_value != original_value:
                                        audio.tags[mp4_field] = [new_value]
                                        metadata_changed = True
                                        log(f"Updated '{field}' metadata in '{file_path.name}' from '{original_value}' to '{new_value}'", "debug")

                    if metadata_changed:
                        audio.save()
                except Exception as e:
                    log(f"Error processing file '{file_path.name}': {e}", "error")

    def find_unwanted_files(self):
        """
        Find and remove unwanted files from the podcast folder.
        """
        announce("Checking if there are episodes we don't want", "info")
        for file_path in Path(self.podcast.folder_path).rglob('*'):
            if file_path.is_file() and any(unwanted_file.lower() in file_path.name.lower() for unwanted_file in self.unwanted_files):
                if ask_yes_no(f"Would you like to remove '{file_path.name}'"):
                    file_path.unlink()
                    self.podcast.analyzer.remove_file(file_path)

    def pad_episode_numbers(self):
        """
        Pad episode numbers with zeros to make them consistent
        """
        pattern = re.compile(self.config.get('episode_pattern', r'(Ep\.?|Episode|E|Part)(\s*)(\d+)'), re.IGNORECASE)

        files_with_episodes = []

        for filename in Path(self.podcast.folder_path).rglob('*'):
            match = pattern.search(filename.name)
            if match:
                episode_number = int(match.group(3))
                files_with_episodes.append((filename, episode_number))

        if not files_with_episodes:
            log("No files with episode numbers found", "debug")
            return

        max_episode_number = max(ep_num for _, ep_num in files_with_episodes)
        num_digits = len(str(max_episode_number))

        def pad_episode_number(match):
            prefix = match.group(1)
            space = match.group(2)
            episode_number = int(match.group(3))
            padded_episode = str(episode_number).zfill(num_digits)
            return f"{prefix}{space}{padded_episode}"

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
        has_trailer = False
        trailer_patterns = self.config.get('trailer_patterns', [])
        trailer_regex = re.compile('|'.join([re.escape(pattern) for pattern in trailer_patterns]), re.IGNORECASE)
        if episode_titles and trailer_regex.search(episode_titles[0]):
            log(f"The first episode '{episode_titles[0]}' matches a trailer pattern, adjusting episode numbers -1.", "debug")
            has_trailer = True

        for date, files in files_without_episode_numbers.items():
            max_episode_number = len(episode_titles)
            num_digits = len(str(max_episode_number))

            for index, file_path in enumerate(files):
                normalized_filename = normalize_string(file_path.name)
                for episode_number, title in enumerate(episode_titles, start=1):
                    if has_trailer:
                        episode_number -= 1
                    normalized_title = normalize_string(title)
                    if normalized_title in normalized_filename:
                        padded_episode = str(episode_number).zfill(num_digits)

                        original_title = re.sub(rf'\b{date}\b ', '', file_path.name).strip()
                        title_parts = re.split(self.config.get('title_split_pattern', r' - (?=[^-]*$)'), original_title)
                        
                        new_filename = filename_format.format(prefix=title_parts[0].strip(), date=date, episode=padded_episode, suffix=title_parts[1].strip())
                        new_path = file_path.with_name(new_filename)

                        file_path.rename(new_path)
                        log(f"Renamed '{file_path}' to '{new_path}'", "debug")
                        self.podcast.analyzer.update_file_path(file_path, new_path)
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

    def check_split(self):
        """
        Check if the podcast is active, and if it is and spans multiple years,
        split it into multiple folders -- one folder from the start up until the
        last full year, and another folder for the current year.
        """
        if self.podcast.completed:
            log("Skipping split check, podcast is marked as complete", "debug")
            return
        
        split = self.config.get('split', False)
        if not split:
            log("Skipping split check, split is false", "debug")
            return

        start_year = int(self.podcast.analyzer.earliest_year)
        last_year = int(self.podcast.analyzer.last_episode_date[:4])
        current_year = datetime.now().year

        if (not start_year or not last_year) or start_year == last_year or last_year != current_year:
            log("Skipping split check, podcast does not span multiple years", "debug")
            return

        current_folder = self.podcast.folder_path.parent / f"{self.podcast.name} --CURRENT--"

        if current_folder.exists():
            log(f"Current year folder '{current_folder}' already exists", "debug")
            if not ask_yes_no(f"'{current_folder.name}' already exists, proceed with split anyway?"):
                log("Skipping split check, user chose not to proceed - folder exists", "debug")
                return
    
        if not current_folder.exists():
            current_folder.mkdir()
        
        for date, year_list in self.podcast.analyzer.file_dates.items():
            year = int(date[:4])
            if year == current_year:
                for file_path in year_list[:]:
                    if not file_path.exists():
                        log(f"File '{file_path}' does not exist", "debug")
                        continue
                    new_path = current_folder / file_path.name
                    if new_path.exists():
                        log(f"File '{new_path}' already exists", "debug")
                        if not ask_yes_no(f"'{new_path.name}' already exists, overwritet?"):
                            log("Skipping file", "debug")
                            continue
                        log("Deleting file", "debug")
                        new_path.unlink()

                    file_path.rename(new_path)
                    log(f"Moved '{file_path}' to '{new_path}'", "debug")
                    self.podcast.analyzer.remove_file(file_path)

        self.duplicate_metadata(current_folder)

        announce(f"Podcast split into two folders, current year is in folder appended with --CURRENT--", "info")
    
    def duplicate_metadata(self, new_folder):
        self.podcast.metadata.duplicate(new_folder)
        self.podcast.image.duplicate(new_folder)
        self.podcast.rss.duplicate(new_folder)

    def organize_files(self):
        """
        Organize the episode files in the podcast folder.
        """
        self.check_split()
        self.rename_folder()
        with spinner("Organizing episode files") as spin:
            self.rename_files()
            spin.ok("✔")

        self.find_unwanted_files()
        self.check_numbering()
        self.update_file_metadata()

    def rename_folder(self):
        """
        Rename the podcast folder based on the podcast name and last episode date.
        """
        if '(' in self.podcast.folder_path.name:
            return
        date_format_short = self.config.get('date_format_short', '%Y-%m-%d')
        date_format_long = self.config.get('date_format_long', '%B %d %Y')
        start_year_str = str(self.podcast.analyzer.earliest_year) if self.podcast.analyzer.earliest_year else "Unknown"
        real_start_year_str = str(self.podcast.analyzer.real_first_episode_date)[:4] if self.podcast.analyzer.real_first_episode_date else "Unknown"
        first_episode_date_str = format_last_date(self.podcast.analyzer.first_episode_date, date_format_long) if self.podcast.analyzer.first_episode_date else "Unknown"
        last_episode_date_str = format_last_date(self.podcast.analyzer.last_episode_date, date_format_long) if self.podcast.analyzer.last_episode_date else "Unknown"
        last_episode_date_dt = datetime.strptime(self.podcast.analyzer.last_episode_date, date_format_short) if self.podcast.analyzer.last_episode_date != "Unknown" else None
        real_last_episode_date_dt = datetime.strptime(self.podcast.analyzer.real_last_episode_date, date_format_short) if self.podcast.analyzer.real_last_episode_date != "Unknown" else None
        last_year_str = str(last_episode_date_dt.year) if last_episode_date_dt else "Unknown"
        new_folder_name = None
        if real_last_episode_date_dt != last_episode_date_dt:
            if ask_yes_no(f'Would you like to rename the folder to {self.podcast.name} ({start_year_str}-{last_year_str})'):
                new_folder_name = f"{self.podcast.name} ({start_year_str}-{last_year_str})"
        if not new_folder_name and start_year_str != real_start_year_str:
            if ask_yes_no(f'Would you like to rename the folder to {self.podcast.name} ({first_episode_date_str}-{last_episode_date_str})'):
                new_folder_name = f"{self.podcast.name} ({first_episode_date_str}-{last_episode_date_str})"
        if not new_folder_name and last_episode_date_dt and datetime.now() - last_episode_date_dt > timedelta(days=self.config.get('completed_threshold_days', 365)):
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
