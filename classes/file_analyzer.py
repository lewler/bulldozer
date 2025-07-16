# file_analyzer.py

import mutagen
import re
import random
import subprocess
from collections import defaultdict
from datetime import datetime
from email.utils import parsedate_to_datetime
from mutagen.mp3 import MP3
from mutagen.mp4 import MP4
from mutagen.mp3 import BitrateMode
from mutagen.easyid3 import EasyID3
from dateutil.parser import parse  # Import dateutil parser
from mutagen.id3 import TXXX  # Import TXXX for accessing custom tags
from .utils import spinner, log

class FileAnalyzer:
    def __init__(self, podcast, config):
        """
        Initialize the FileAnalyzer with the podcast and configuration.
        
        :param podcast: The podcast object containing information about the podcast.
        :param config: The configuration settings.

        The FileAnalyzer class is responsible for analyzing the audio files in the podcast folder.
        """
        self.podcast = podcast
        self.config = config
        self.file_dates = defaultdict(list)
        self.earliest_year = None
        self.last_episode_date = None
        self.real_last_episode_date = None
        self.first_episode_date = None
        self.real_first_episode_date = None
        self.original_files = None
        self.mediainfo_output = None

    def analyze_files(self):
        """
        Analyze the audio files in the podcast folder.
        """
        self.bitrates = defaultdict(list)
        self.file_formats = defaultdict(list)
        if self.file_dates and not self.original_files:
            self.original_files = self.file_dates
        self.file_dates = defaultdict(list)
        self.all_vbr = True
        self.durations = defaultdict(list)
        all_bad = True
        trailer_patterns = self.config.get('trailer_patterns', [])
        with spinner("Checking files") as spin:
            for file_path in self.podcast.folder_path.iterdir():
                if file_path.suffix.lower() in ['.mp3', '.m4a']:
                    metadata = self.analyze_audio_file(file_path, trailer_patterns)
                    if metadata:
                        all_bad = False
                        self.process_metadata(metadata, file_path)
            if all_bad:
                spin.fail("✖")
                log("No valid audio files found", "critical")
                return
            # sort self.file_dates
            self.file_dates = dict(sorted(self.file_dates.items()))
            self.get_date_range()
            
            # Run mediainfo if enabled in config
            if self.config.get('include_mediainfo', True):
                self.run_mediainfo()
            
            spin.ok("✔")

    def analyze_audio_file(self, file_path, trailer_patterns):
        """
        Analyze an individual audio file and extract metadata.

        :param file_path: The path to the audio file.
        :return: The metadata of the audio file.
        """
        audiofile = mutagen.File(file_path)
        if not audiofile or not hasattr(audiofile, 'info'):
            log(f"Unsupported or corrupt file, skipping: {file_path}", "warning")
            return None

        if not any(pattern.lower() in file_path.name.lower() for pattern in trailer_patterns):
            if isinstance(audiofile, MP3) or isinstance(audiofile, MP4):
                if audiofile.info.length:
                    self.durations[audiofile.info.length].append(file_path)

        metadata = {}
        if isinstance(audiofile, MP3):
            # Access 'TDRC' frame directly for recording date
            try:
                log(f"MP3 tags for '{file_path.name}': {audiofile.tags.pprint()}", "debug")
                if ('TDRC' in audiofile.tags and
                    audiofile.tags['TDRC'].text and
                    audiofile.tags['TDRC'].text[0]):

                    tdrc = audiofile.tags['TDRC']
                    date_value = tdrc.text[0]
                    # Convert date_value to string before stripping
                    date_str = str(date_value).strip()

                    if date_str:
                        metadata['recording_date'] = date_str
                        log(f"Found 'TDRC' tag: '{date_str}' in '{file_path.name}'", "debug")
                    else:
                        # Proceed to fallback methods
                        metadata['recording_date'] = self.mp3_date_extract_alternatives(audiofile, file_path)
                else:
                    # Proceed to fallback methods
                    metadata['recording_date'] = self.mp3_date_extract_alternatives(audiofile, file_path)
            except Exception as e:
                log(f"Error reading tags from '{file_path.name}': {e}", "error")
                metadata['recording_date'] = None

            metadata['bitrate'] = round(audiofile.info.bitrate / 1000)
            metadata['bitrate_mode'] = "VBR" if audiofile.info.bitrate_mode == BitrateMode.VBR else "CBR"

        elif isinstance(audiofile, MP4):
            metadata['recording_date'] = audiofile.tags.get("\xa9day", [None])[0]
            metadata['bitrate'] = round(audiofile.info.bitrate / 1000)
            metadata['bitrate_mode'] = "CBR" if metadata['bitrate'] else "VBR"
        else:
            log(f"Unsupported audio format, skipping: {file_path}", "warning")
            return None

        if metadata['bitrate_mode'] != "VBR":
            self.all_vbr = False

        return metadata

    def mp3_date_extract_alternatives(self, audiofile, file_path):
        """
        Extract the recording date from alternative tags.

        :param audiofile: The audio file object.
        :param file_path: The path to the audio file.
        :return: The extracted date as a string, or None if not found.
        """
        try:
            easy_tags = EasyID3(file_path)
            log(f"EasyID3 tags for '{file_path.name}': {easy_tags.pprint()}", "debug")
            # Try to get date from different tags
            date = easy_tags.get('date', [None])[0]
            if not date:
                date = easy_tags.get('originaldate', [None])[0]
            if not date:
                date = easy_tags.get('year', [None])[0]
            if date:
                log(f"Found date in EasyID3 tags: '{date}' in '{file_path.name}'", "debug")
                return date
            else:
                # Look for 'releasedate' in TXXX frames
                txxx_tags = audiofile.tags.getall('TXXX')
                releasedate = None
                for tag in txxx_tags:
                    log(f"TXXX tag: desc='{tag.desc}', text='{tag.text}'", "debug")
                    if 'releasedate' in tag.desc.lower():
                        releasedate = tag.text[0].strip()
                        log(f"Found 'releasedate' in TXXX tags: '{releasedate}' in '{file_path.name}'", "debug")
                        break
                if releasedate:
                    log(f"Set 'recording_date' to 'releasedate': '{releasedate}' for '{file_path.name}'", "debug")
                    return releasedate
                else:
                    log(f"No date tag found in '{file_path.name}'", "warning")
                    return None
        except Exception as e:
            log(f"Error reading EasyID3 tags from '{file_path.name}': {e}", "error")
            return None
    
    def get_date_range(self):
        """
        Get the date range of the audio files.
        """
        self.file_dates = {k: v for k, v in self.file_dates.items() if v}
        self.earliest_year = None
        self.first_episode_date = None
        self.real_first_episode_date = None
        self.last_episode_date = None
        self.real_last_episode_date = None

        for date_str in self.file_dates.keys():
            if date_str != "Unknown":
                try:
                    year = int(str(date_str)[:4])
                except ValueError:
                    log(f"Invalid date string '{date_str}' encountered.", "warning")
                    continue

                if self.earliest_year is None or (year and year < self.earliest_year):
                    self.earliest_year = year
                if self.first_episode_date is None or date_str < self.first_episode_date:
                    self.real_first_episode_date = self.first_episode_date = date_str
                if self.last_episode_date is None or date_str > self.last_episode_date:
                    self.real_last_episode_date = self.last_episode_date = date_str
            else:
                # Handle files with unknown dates separately if needed
                log(f"Encountered file with unknown date.", "warning")
                continue

        # If we have original files (from previous runs), update real first and last dates
        if self.original_files:
            for date_str in self.original_files.keys():
                if date_str != "Unknown":
                    if self.real_first_episode_date is None or (date_str and date_str < self.real_first_episode_date):
                        self.real_first_episode_date = date_str
                    if self.real_last_episode_date is None or (date_str and date_str > self.real_last_episode_date):
                        self.real_last_episode_date = date_str

    def process_metadata(self, metadata, file_path):
        """
        Process the metadata of an audio file.

        :param metadata: The metadata of the audio file.
        :param file_path: The path to the audio file.
        """
        recording_date = metadata.get('recording_date')
        date_str = "Unknown"
        year = None

        if recording_date:
            date_str_raw = str(recording_date)
            parsed = False
            date_obj = None

            # Add debug logging
            log(f"Processing recording_date: '{date_str_raw}' for file '{file_path.name}'", "debug")

            # Define possible date formats
            date_formats = [
                '%Y-%m-%d',
                '%Y',
                '%a, %d %b %Y %H:%M:%S %z',    # 'Thu, 02 Nov 2023 16:31:53 -0000'
                '%a, %d %b %Y %H:%M:%S %Z',
                '%d %b %Y %H:%M:%S %z',
                '%d %b %Y %H:%M:%S %Z',
            ]

            # Try parsing with the defined formats
            for fmt in date_formats:
                try:
                    date_obj = datetime.strptime(date_str_raw, fmt)
                    parsed = True
                    break
                except ValueError:
                    continue

            if not parsed:
                try:
                    # Use dateutil.parser.parse for flexible parsing
                    date_obj = parse(date_str_raw)
                    parsed = True
                except (ValueError) as e:
                    log(f"Failed to parse date '{date_str_raw}' using dateutil: {e}", "warning")

            if not parsed:
                try:
                    # Fallback to parsedate_to_datetime
                    date_obj = parsedate_to_datetime(date_str_raw)
                    if date_obj is not None:
                        parsed = True
                except (TypeError, ValueError, IndexError):
                    pass

            if parsed and date_obj:
                year = date_obj.year
                date_str = date_obj.strftime('%Y-%m-%d')
                log(f"Parsed date: '{date_str}'", "debug")
            else:
                log(f"Invalid recording date format for file '{file_path.name}': '{date_str_raw}'", "warning")
                date_str = "Unknown"
        else:
            # Try to extract date from file name
            date_pattern = re.compile(r'\b(\d{4}-\d{2}-\d{2})\b')
            match = date_pattern.search(file_path.name)
            if match:
                date_str = match.group(1)
                try:
                    date_obj = datetime.strptime(date_str, '%Y-%m-%d')
                    year = date_obj.year
                except ValueError:
                    log(f"Invalid date in file name for file '{file_path}': '{date_str}'", "warning")
                    date_str = "Unknown"
            else:
                # Use file modification date as a last resort
                try:
                    timestamp = file_path.stat().st_mtime
                    date_obj = datetime.fromtimestamp(timestamp)
                    date_str = date_obj.strftime('%Y-%m-%d')
                    year = date_obj.year
                    log(f"Using file modification date for {file_path}: '{date_str}'", "info")
                except Exception as e:
                    log(f"Failed to get file modification date for {file_path}: {e}", "error")
                    date_str = "Unknown"

        # Continue processing even if date is unknown
        self.file_dates[date_str].append(file_path)

        bitrate = metadata.get('bitrate', None)
        bitrate_mode = metadata.get('bitrate_mode', 'Unknown')
        bitrate_str = "VBR" if "vbr" in bitrate_mode.lower() else f"{bitrate} kbps" if bitrate else "Unknown"
        self.bitrates[bitrate_str].append(file_path)

        file_format = file_path.suffix.lower()[1:]
        self.file_formats[file_format].append(file_path)

    def get_average_duration(self):
        """
        Get the average duration of the audio files.
        
        :return: The average duration in seconds.
        """
        durations = list(self.durations.keys())
        if not durations:
            return None
        return sum(durations) / len(durations)
    
    def get_longest_duration(self):
        """
        Get the longest duration of the audio files.
        
        :return: The longest duration in seconds.
        """
        durations = list(self.durations.keys())
        if not durations:
            return None
        return max(durations)
    
    def get_shortest_duration(self):
        """
        Get the shortest duration of the audio files.
        
        :return: The shortest duration in seconds.
        """
        durations = list(self.durations.keys())
        if not durations:
            return None
        return min(durations)
    
    def remove_file(self, file_path):
        """
        Remove a file from bitrates and file formats.
        
        :param file_path: The path to the file to remove.
        """
        for bitrate_list in self.bitrates.values():
            if file_path in bitrate_list:
                bitrate_list.remove(file_path)
                log(f"Removed bitrate path: {file_path}", "debug")
        for format_list in self.file_formats.values():
            if file_path in format_list:
                format_list.remove(file_path)
                log(f"Removed format list path: {file_path}", "debug")
        for date_list in self.file_dates.values():
            if file_path in date_list:
                date_list.remove(file_path)
                log(f"Removed date list path: {file_path}", "debug")

        self.get_date_range()

    def run_mediainfo(self):
        """
        Run mediainfo on a random audio file in the folder and store the output.
        """
        audio_files = []
        for file_path in self.podcast.folder_path.iterdir():
            if file_path.suffix.lower() in ['.mp3', '.m4a']:
                audio_files.append(file_path)
        
        if not audio_files:
            log("No audio files found for mediainfo analysis", "warning")
            return
        
        # Select a random file
        random_file = random.choice(audio_files)
        
        try:
            # Check if mediainfo is available
            result = subprocess.run(['which', 'mediainfo'], 
                                  capture_output=True, text=True)
            if result.returncode != 0:
                log("mediainfo not installed, skipping mediainfo analysis", "info")
                return
            
            # Run mediainfo on the random file
            result = subprocess.run(['mediainfo', str(random_file)], 
                                  capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                self.mediainfo_output = {
                    'file': random_file.name,
                    'output': result.stdout
                }
                log(f"mediainfo analysis completed on {random_file.name}", "debug")
            else:
                log(f"mediainfo failed with return code {result.returncode}: {result.stderr}", "error")
                
        except subprocess.TimeoutExpired:
            log("mediainfo command timed out", "error")
        except Exception as e:
            log(f"Error running mediainfo: {e}", "error")

    def update_file_path(self, old_path, new_path):
        """
        Update the file path in bitrates and file formats.
        
        :param old_path: The old path to the file.
        :param new_path: The new path to the file.
        """
        for bitrate_list in self.bitrates.values():
            if old_path in bitrate_list:
                bitrate_list.remove(old_path)
                bitrate_list.append(new_path)
                log(f"Updated bitrate path: {old_path} -> {new_path}", "debug")
        for format_list in self.file_formats.values():
            if old_path in format_list:
                format_list.remove(old_path)
                format_list.append(new_path)
                log(f"Updated format list path: {old_path} -> {new_path}", "debug")
        for date_list in self.file_dates.values():
            if old_path in date_list:
                date_list.remove(old_path)
                date_list.append(new_path)
                log(f"Updated date list path: {old_path} -> {new_path}", "debug")
