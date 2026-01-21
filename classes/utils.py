# utils.py
import subprocess
import logging
import yaml
import re
import shutil
import fnmatch
import requests
import gzip
import zlib
import platform
import os
from datetime import datetime
from contextlib import contextmanager
from pathlib import Path
from yaspin import yaspin
from titlecase import titlecase
from logging.handlers import RotatingFileHandler
from .cache import Cache

# Global state to track if user selected "yes to all"
_yes_to_all = False

def reset_yes_to_all():
    """
    Reset the "yes to all" flag to False.
    This should be called after file overwrite sections are complete.
    """
    global _yes_to_all
    _yes_to_all = False

def run_command(command, progress_description=None, track_progress=False, total_episodes=None):
    """
    Run a shell command and return the output.

    :param command: The shell command to run.
    :param progress_description: The description to display during progress.
    :param track_progress: If True, track the progress of the command.
    :param total_episodes: The total number of episodes to track progress.

    :return: The output of the command and the return code.
    """
    output = []
    episode_count = 0
    completed_episodes = set()  # Track unique episode numbers/completions to avoid double counting
    log(f"Running command: {command}", "info")
    if progress_description:
        log(f"Progress description: {progress_description}", "info")
    if track_progress and total_episodes:
        log(f"Tracking progress for {total_episodes} episodes", "info")
    try:
        with spinner(progress_description) as spin:
            process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            log(f"Command process started with PID: {process.pid}", "info")
            for line in iter(process.stdout.readline, b''):
                if line:
                    decoded_line = line.decode('utf-8', errors='replace').strip()
                    output.append(decoded_line)
                    # Log each line at DEBUG level for detailed output visibility
                    log(f"Command output: {decoded_line}", "debug")
                    if track_progress and "Download complete" in decoded_line:
                        # Only count episode downloads (lines with [N] pattern), not image downloads
                        # The [N] pattern indicates an episode download, not just any download
                        if re.search(r'\[\d+\]', decoded_line):
                            # The [N] in podcast-dl output is a thread/batch identifier, not episode number
                            # Count each unique "Download complete" line to track actual episode completions
                            # Use the full line as a key to avoid counting the same episode twice
                            line_hash = hash(decoded_line)
                            if line_hash not in completed_episodes:
                                completed_episodes.add(line_hash)
                                episode_count = len(completed_episodes)
                                spin.text = f"{progress_description} ({episode_count}/{total_episodes})"
                                log(f"Download progress: {episode_count}/{total_episodes} episodes complete", "info")
            process.wait()
            log(f"Command process completed with return code: {process.returncode}", "info")
            
            # Log full output at DEBUG level for debugging
            if output:
                full_output = '\n'.join(output)
                log(f"Command full output ({len(output)} lines):\n{full_output}", "debug")
            
            if process.returncode == 0:
                spin.ok("✔")
            else:
                spin.fail("✖")
                log(f"Command failed with return code: {process.returncode}", "info")
                if output:
                    log(f"Command output (last 10 lines): {chr(10).join(output[-10:])}", "info")
    except Exception as e:
        log(f"Exception occurred while running command: {type(e).__name__}: {str(e)}", "info")
        log(f"Exception details: {e}", "debug")
        raise
    return '\n'.join(output), process.returncode

@contextmanager
def spinner(text):
    """
    Create a spinner context manager.

    :param text: The text to display with the spinner.
    :return: The spinner object.
    """
    with yaspin(text=text, color="cyan") as spin:
        yield spin

def deep_merge(base, user):
    for key, value in user.items():
        if isinstance(value, dict) and key in base and isinstance(base[key], dict):
            deep_merge(base[key], value)
        else:
            base[key] = value

def find_extra_keys(base_config, user_config, path=""):
    """
    Recursively find extra keys in the user's config that are not present in the default config.

    :param base_config: The default configuration.
    :param user_config: The user's configuration.
    :param path: The current path of keys for error reporting.
    :return: A list of extra keys.
    """
    extra_keys = []

    for key in user_config:
        current_path = f"{path}.{key}" if path else key
        if key not in base_config:
            extra_keys.append(current_path)
        elif isinstance(user_config[key], dict) and isinstance(base_config.get(key), dict):
            extra_keys.extend(find_extra_keys(base_config[key], user_config[key], current_path))

    return extra_keys

def check_config():
    """
    Check the configuration settings.

    :return: True if the configuration is valid, False otherwise.
    """
    global config
    base_config_file = Path("config.default.yaml")
    user_config_file = Path("config.yaml")
    if not base_config_file.exists():
        log("'config.default.yaml' not found.", "error")
        return False
    with open(base_config_file, 'r') as base_file:
        base_config = yaml.safe_load(base_file)

    if not base_config:
        log("Failed to load base config file.", "error")
        return False
    
    try:
        with open(user_config_file, 'r') as user_file:
            user_config = yaml.safe_load(user_file)
    except FileNotFoundError:
        log("'config.yaml' not found, no check needed.", "debug")
        announce("No user config found. It can therefore not be invalid, yay!", "celebrate")
        return True

    extra_keys = find_extra_keys(base_config, user_config)
    if extra_keys:
        announce("Extra keys found in user config:", "warning")
        for key in extra_keys:
            announce(f"- {key}")
        return False

    announce("User config is valid, yay!", "celebrate")
    return True

def load_config():
    """
    Load the configuration settings.

    :return: The configuration settings.
    """
    global config
    base_config_file = Path("config.default.yaml")
    user_config_file = Path("config.yaml")
    if not base_config_file.exists():
        log("'config.default.yaml' not found.", "error")
        return None
    with open(base_config_file, 'r') as base_file:
        base_config = yaml.safe_load(base_file)

    if not base_config:
        log("Failed to load base config file.", "error")
        return None
    
    if user_config_file.exists():
        try:
            with open(user_config_file, 'r') as user_file:
                user_config = yaml.safe_load(user_file)
        except FileNotFoundError:
            log("'config.yaml' could not be loaded.", "error")
            user_config = {}

        deep_merge(base_config, user_config)
        
    config = base_config

    return config

def setup_logging(log_level, config=None):
    """
    Setup the logging configuration.

    :param log_level: The log level to set.
    :param config: The configuration settings.
    """
    config = config or {}
    logs = Path("logs")
    logs.mkdir(exist_ok=True)
    
    logfile_size_mb = config.get("logfile_size_mb", 1)
    logfile_count = config.get("logfile_count", 5)
    file_handler = RotatingFileHandler(
        "logs/bulldozer.log",
        maxBytes=logfile_size_mb * 1024 * 1024,
        backupCount=logfile_count
    )
    
    config_log_level = config.get("log_level", "WARNING").upper()
    effective_log_level = log_level.upper() if log_level else config_log_level
    
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    file_handler.setFormatter(formatter)
    
    root_logger = logging.getLogger()
    root_logger.setLevel(effective_log_level)
    
    # Add console handler if DEBUG or INFO level is set
    if not root_logger.hasHandlers():
        root_logger.addHandler(file_handler)
        # Add console handler for INFO and above when DEBUG/INFO level is set
        if effective_log_level in ['DEBUG', 'INFO']:
            console_handler = logging.StreamHandler()
            console_handler.setLevel(logging.INFO if effective_log_level == 'INFO' else logging.DEBUG)
            console_formatter = logging.Formatter('%(levelname)s - %(message)s')
            console_handler.setFormatter(console_formatter)
            root_logger.addHandler(console_handler)
    
    log(f"Log level set to {effective_log_level}", "debug")

def log(text, level="info"):
    """
    Log a message with the specified level.

    :param text: The message to log.
    :param level: The log level.
    """
    if level == "info":
        logging.info(text)
    elif level == "warning":
        logging.warning(text)
    elif level == "error":
        logging.error(text)
    elif level == "critical":
        logging.critical(text)
    elif level == "debug":
        logging.debug(text)
    else:
        raise ValueError(f"Invalid log level: {level}")
    
def announce(text, type=None):
    """
    Announce a message with a specific type.

    :param text: The message to announce.
    :param type: The type of announcement.
    """
    prepend = "  "
    if type == "critical":
        prepend = "🛑"
    if type == "error":
        prepend = "❌"
    if type == "warning":
        prepend = "❗️"
    if type == "info":
        prepend = "❕"
    if type == "celebrate":
        prepend = "🎉"
    print(f"{prepend}{text}")

def ask_yes_no(question, allow_all=False):
    """
    Ask a yes/no question.

    :param question: The question to ask.
    :param allow_all: If True, allows "A" option to answer "yes" to all subsequent file overwrite prompts.
    :return: True if the answer is yes, False otherwise.
    """
    global _yes_to_all
    
    # Only auto-answer if this is a file overwrite prompt (allow_all=True) AND user selected "A" previously
    # This ensures "yes to all" only applies to file overwrite prompts, not other prompts
    if _yes_to_all and allow_all:
        log(f"Auto-answering 'yes' to file overwrite prompt (allow_all=True)", "debug")
        return True
    
    prompt_suffix = " (y/N/A for all)" if allow_all else " (y/N)"
    
    while True:
        response = input(f"❓{question}{prompt_suffix}: ").strip().lower()
        if response == 'y':
            return True
        elif response == 'a' and allow_all:
            _yes_to_all = True
            announce("All subsequent file overwrite prompts will be answered 'yes'", "info")
            return True
        else:
            return False
        
def take_input(prompt):
    """
    Take input from the user.

    :param prompt: The prompt to display.
    :return: The user's input.
    """
    while True:
        response = input(f"❓{prompt}: ").strip()
        if response == '':
            return None
        else:
            return response
        
def get_metadata_directory(folder_path, config):
    """
    Get the path to the metadata directory.

    :param folder_path: The path to the podcast folder.
    :param config: The configuration settings.
    :return: The path to the metadata directory.
    """
    return folder_path / get_metadata_directory_name(config)
        
def get_metadata_directory_name(config):
    """
    Get the name of the metadata directory.

    :param config: The configuration settings.
    :return: The name of the metadata directory.
    """
    return config.get('metadata_directory', 'Metadata')

def special_capitalization(word, config, previous_word=None, **kwargs):
    """
    Apply special capitalization rules to a word.

    :param word: The word to capitalize.
    :param config: The configuration settings.
    :return: The capitalized word.
    """
    patterns_uppercase = config.get('force_uppercase', [])
    patterns_titlecase = config.get('force_titlecase', [])
    patterns_skip = config.get('skip_capitalization', [])
    pattern_previous_word = config.get('pattern_previous_word', r'\b(\d+\.)|\b\d+\b|-|\b\w+_?')
    for pattern in patterns_uppercase:
        if re.match(pattern, word, re.IGNORECASE):
            return word.upper()
    for pattern in patterns_titlecase:
        if re.match(pattern, word, re.IGNORECASE):
            if (previous_word and re.match(pattern_previous_word, previous_word)) or not previous_word:
                return word.title()
    for pattern in patterns_skip:
        if re.search(pattern, word, re.IGNORECASE):
            return word
    return None

def titlecase_filename(file_path, config):
    """
    Titlecase the filename with special capitalization rules.

    :param file_path: The path to the file.
    :param config: The configuration settings.
    :return: The titlecased filename.
    """
    new_stem = ''
    previous_word = ''
    # Super hacky, but I just had to get it to work for now
    for word in file_path.stem.split():
        new_stem += special_capitalization(word, config, previous_word) or titlecase("Welcome " + word + " to the jungle")
        pattern = r"welcome\s*| to the jungle"
        new_stem = re.sub(pattern, '', new_stem, flags=re.IGNORECASE)
        new_stem += ' '
        previous_word = word

    return new_stem.strip() + file_path.suffix

@contextmanager
def open_file_case_insensitive(filename, folder_path, mode='r'):
        """
        Open a file in a case-insensitive manner.

        :param filename: The name of the file to open.
        :param folder_path: The path to the folder to search in.
        :param mode: The mode to open the file in.
        :return: The file object.
        """
        target_file_name = filename.lower()

        for file in folder_path.iterdir():
            if file.is_file() and file.name.lower() == target_file_name:
                f = file.open(mode)
                try:
                    yield f
                finally:
                    f.close()
                return
        log(f"No file matching '{filename}' found in '{folder_path}'", "debug")
        yield None

def archive_metadata(file_path, target_path):
    """
    Archive the metadata file to a target path.

    :param file_path: The path to the metadata file.
    :param target_path: The path to the target folder.
    :return: True if the file was archived successfully, False otherwise.
    """
    if not target_path:
        return False
    target_path = Path(target_path)
    if not target_path.exists():
        target_path.mkdir(parents=True)
    target_file_path = target_path / file_path.name
    shutil.copy(file_path, target_file_path)
    log(f"Archived metadata file to {target_file_path}", "debug")
    return True

def format_last_date(date_str, date_format_long="%B %d %Y"):
    """
    Format the last date in a long format.

    :param date_str: The date string to format.
    :param date_format_long: The long date format.
    :return: The formatted date string
    """
    dt = datetime.strptime(date_str, "%Y-%m-%d")
    return dt.strftime(date_format_long)

def find_case_insensitive_files(pattern, folder_path='.'):
    """
    Find files in the podcast folder that match a pattern in a case-insensitive manner.

    :param pattern: The pattern to match against the file names.
    :param folder_path: The path to the folder to search in.
    :return: A list of file paths that match the pattern.
    """
    matches = []
    pattern = pattern.lower()
    for file in folder_path.iterdir():
        if fnmatch.fnmatch(file.name.lower(), pattern):
            matches.append(folder_path / file.name)
    return matches

def get_from_cache(key, mode='r'):
    """
    Get data from the cache.

    :param key: The key to get the data for.
    :return: The data.
    """
    global config
    cache = Cache(config)
    return cache.get(key, mode)

def write_to_cache(key, data, mode='w'):
    """
    Write data to the cache.

    :param key: The key to write the data to.
    :param data: The data to write.
    :return: True if the data was written successfully, False otherwise.
    """
    global config
    cache = Cache(config)
    return cache.write(key, data, mode)

def normalize_string(string):
    """
    Normalize a string by removing non-alphanumeric characters and converting it to lowercase.

    :param string: Input string
    :return: Normalized string
    """
    return re.sub(r'[^a-zA-Z0-9]', '', string).lower()

def perform_replacements(string, file_replacements):
    """
    Perform a series of regsub replacements on a string.

    :param string: The string to perform the replacements on.
    :param file_replacements: The replacements to perform.

    :return: The modified string.
    """
    for item in file_replacements:
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
                previous = None
                while previous != string:
                    previous = string
                    string = re.sub(pattern, replacement, string)
            else:
                string = re.sub(pattern, replacement, string)

    return string

def copy_file(source, target):
    """
    Copy a file from the source to the target.

    :param source: The source file path.
    :param target: The target file path.
    """
    shutil.copy(source, target)

def convert_paths_to_strings(data):
    if isinstance(data, dict):
        return {key: convert_paths_to_strings(value) for key, value in data.items()}
    elif isinstance(data, list):
        return [convert_paths_to_strings(item) for item in data]
    elif isinstance(data, Path):
        return str(data)
    else:
        return data
    
def download_file(url, target_path):
    """
    Download a file from a URL.

    :param url: The URL of the file to download.
    :param target_path: The path to save the file to.
    :return: True
    """
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate",
        "Connection": "keep-alive"
    }

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        content = response.content
        encoding = (response.headers.get("Content-Encoding") or "").lower()
        if encoding == "br":
            try:
                import brotli
                content = brotli.decompress(content)
            except Exception as e:
                log("Failed to decompress Brotli content", "error")
                log(e, "debug")
                return False
        elif encoding in {"gzip", "x-gzip"}:
            try:
                content = gzip.decompress(content)
            except OSError as e:
                log("Gzip decoding failed; using raw content instead.", "debug")
                log(e, "debug")
        elif encoding == "deflate":
            try:
                content = zlib.decompress(content)
            except zlib.error as e:
                log("Deflate decoding failed; using raw content instead.", "debug")
                log(e, "debug")
        else:
            if content.startswith(b"\x1f\x8b"):
                try:
                    content = gzip.decompress(content)
                except OSError as e:
                    log("Gzip magic detected but decoding failed; using raw content instead.", "debug")
                    log(e, "debug")
            elif content.startswith(b"\x78\x01") or content.startswith(b"\x78\x9c") or content.startswith(b"\x78\xda"):
                try:
                    content = zlib.decompress(content)
                except zlib.error as e:
                    log("Deflate magic detected but decoding failed; using raw content instead.", "debug")
                    log(e, "debug")

        with target_path.open('wb') as file:
            file.write(content)
    except requests.exceptions.RequestException as e:
        log(f"An error occurred while downloading {url}", "error")
        log(e, "debug")
        return False
    except (OSError, zlib.error) as e:
        log(f"An error occurred while decompressing {url}", "error")
        log(e, "debug")
        return False
    
    return True

def check_and_install_podcast_dl():
    """
    Check if podcast-dl command exists.
    
    :return: True if podcast-dl is available, False otherwise.
    """
    log("Checking if podcast-dl is available...", "info")
    
    # Check if podcast-dl already exists
    podcast_dl_path = shutil.which('podcast-dl')
    if podcast_dl_path:
        log(f"podcast-dl found at: {podcast_dl_path}", "info")
        return True
    
    log("podcast-dl not found", "error")
    announce("podcast-dl is not installed. Please install it manually:", "error")
    
    system = platform.system().lower()
    if system == 'linux':
        announce("  For Linux:", "info")
        announce("    curl -L \"$(curl -s https://api.github.com/repos/lightpohl/podcast-dl/releases/latest | grep -o 'https://[^\"]*linux-x64')\" -o ~/.local/bin/podcast-dl && chmod +x ~/.local/bin/podcast-dl", "info")
        announce("  Or via npm:", "info")
        announce("    npm install -g podcast-dl", "info")
    elif system == 'darwin':  # macOS
        announce("  For macOS:", "info")
        announce("    npm install -g podcast-dl", "info")
        announce("  Or via Homebrew:", "info")
        announce("    brew install podcast-dl", "info")
    else:
        announce("  Please visit: https://github.com/lightpohl/podcast-dl for installation instructions", "info")
    
    return False

def check_and_install_mktorrent():
    """
    Check if mktorrent command exists.
    
    :return: True if mktorrent is available, False otherwise.
    """
    log("Checking if mktorrent is available...", "info")
    
    # Check if mktorrent already exists
    mktorrent_path = shutil.which('mktorrent')
    if mktorrent_path:
        log(f"mktorrent found at: {mktorrent_path}", "info")
        return True
    
    log("mktorrent not found", "error")
    announce("mktorrent is not installed. Please install it manually:", "error")
    
    system = platform.system().lower()
    if system == 'linux':
        announce("  For Debian/Ubuntu:", "info")
        announce("    sudo apt-get update && sudo apt-get install -y mktorrent", "info")
        announce("  For RHEL/CentOS/Fedora:", "info")
        announce("    sudo yum install mktorrent  # or sudo dnf install mktorrent", "info")
    elif system == 'darwin':  # macOS
        announce("  For macOS:", "info")
        announce("    brew install mktorrent", "info")
    else:
        announce("  Please visit: https://github.com/Rudde/mktorrent for installation instructions", "info")
    
    return False

def fix_folder_name(name):
    new_name = perform_replacements(name, config.get('title_replacements', [])).strip()
    return titlecase(new_name, callback=lambda word, **kwargs: special_capitalization(word, config, None, **kwargs))

def rename_folder(podcast, name, spin=None):
    new_folder_path = podcast.folder_path.parent / name
    if new_folder_path.exists():
        if spin:
            spin.fail("✖")
        log(f"Folder {new_folder_path} already exists", "critical")
        if not ask_yes_no(f"Folder {new_folder_path} already exists, do you want to overwrite it?"):
            announce("Exiting, cya later!", "info")
            exit(1)
        if spin:
            spin = spinner("Renaming folder")
        shutil.rmtree(new_folder_path)

    podcast.folder_path.rename(new_folder_path)
    log(f"Folder renamed to {new_folder_path}", "debug")
    podcast.folder_path = new_folder_path
    podcast.name = name
