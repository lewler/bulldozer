# torrent_creator.py
from pathlib import Path
from .utils import run_command, log, ask_yes_no

class TorrentCreator:
    def __init__(self, podcast, announce_url, base_dir, tracker_source):
        """
        Initialize the TorrentCreator with the podcast and announce URL.

        :param podcast: The podcast object containing information about the podcast.
        :param announce_url: The announce URL for the torrent.
        :param base_dir: The base directory for the podcast.

        The TorrentCreator class is responsible for creating the torrent file for the podcast.
        """
        self.podcast = podcast
        self.announce_url = announce_url
        self.base_dir = base_dir
        self.tracker_source = tracker_source
        if not self.base_dir:
            self.base_dir = self.podcast.folder_path.parent
        self.base_dir = Path(self.base_dir)

    def calculate_piece_size(self, total_size):
        """
        Calculate the piece size for the torrent.

        :param total_size: The total size of the podcast folder.
        :return: The piece size for the torrent.
        """
        n = 15
        max_n = 24

        while n <= max_n:
            piece_size = 2 ** n
            num_pieces = total_size / piece_size
            if num_pieces <= 1000:
                break
            n += 1
        else:
            n = max_n

        log(f"Calculated piece size: {n}", level="debug")

        return n

    def create_torrent(self, piece_size):
        """
        Create the torrent file for the podcast.

        :param piece_size: The piece size for the torrent.
        """
        torrent_file_path = self.base_dir / f'{self.podcast.folder_path.name}.torrent'
        if torrent_file_path.exists():
            if not ask_yes_no(f"Torrent file {torrent_file_path} already exists. Replace?"):
                return
            log(f"Replacing torrent file: {torrent_file_path}", level="debug")
            torrent_file_path.unlink()
        command = f'mktorrent -p -s {self.tracker_source} -a {self.announce_url} -o "{torrent_file_path}" -l {piece_size} "{self.podcast.folder_path}"'
        log(f"Creating torrent file: {torrent_file_path}", level="debug")
        run_command(command, progress_description="Creating torrent file")
