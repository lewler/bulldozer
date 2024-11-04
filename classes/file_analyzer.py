# file_analyzer.py
import mutagen
from collections import defaultdict
from mutagen.mp3 import MP3
from mutagen.mp4 import MP4
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

    def analyze_files(self):
        """
        Analyze the audio files in the podcast folder.
        """
        self.earliest_year = None
        self.last_episode_date = None
        self.bitrates = defaultdict(list)
        self.file_formats = defaultdict(list)
        self.all_vbr = True
        all_bad = True
        with spinner("Checking files") as spin:
            for file_path in self.podcast.folder_path.iterdir():
                if file_path.suffix.lower() in ['.mp3', '.m4a']:
                    metadata = self.analyze_audio_file(file_path)
                    if metadata:
                        all_bad = False
                        self.process_metadata(metadata, file_path)
            if all_bad:
                spin.fail("✖")
                log("No valid audio files found", "error")
                return
            spin.ok("✔")

    def analyze_audio_file(self, file_path):
        """
        Analyze an individual audio file and extract metadata.
        
        :param file_path: The path to the audio file.
        :return: The metadata of the audio file.
        """
        audiofile = mutagen.File(file_path)
        if not audiofile or not hasattr(audiofile, 'info'):
            log(f"Unsupported or corrupt file, skipping: {file_path}", "warning")
            return None

        metadata = {}
        if isinstance(audiofile, MP3):
            metadata['recording_date'] = audiofile.get("TDRC")
            metadata['bitrate'] = round(audiofile.info.bitrate / 1000)
            metadata['bitrate_mode'] = "VBR" if audiofile.info.bitrate_mode == "vbr" else "CBR"
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

    def process_metadata(self, metadata, file_path):
        """
        Process the metadata of an audio file.
        
        :param metadata: The metadata of the audio file.
        :param file_path: The path to the audio file.
        """
        recording_date = metadata.get('recording_date')
        if recording_date:
            year = int(str(recording_date)[:4])
            date_str = str(recording_date)
        else:
            year = None
            date_str = "Unknown"

        if self.earliest_year is None or (year and year < self.earliest_year):
            self.earliest_year = year
        if self.last_episode_date is None or date_str > self.last_episode_date:
            self.last_episode_date = date_str

        bitrate = metadata['bitrate']
        bitrate_mode = metadata['bitrate_mode']
        bitrate_str = "VBR" if "vbr" in bitrate_mode.lower() else f"{bitrate} kbps"
        self.bitrates[bitrate_str].append(file_path)

        file_format = file_path.suffix.lower()[1:]
        self.file_formats[file_format].append(file_path)
