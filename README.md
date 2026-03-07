# Bulldozer

Bulldozer is a script designed to automate the process of downloading, organizing, analyzing, and creating torrents for podcasts. It's highly customizable, as pretty much everything you might be interested in changing is defined in the configuration file.

## Features

- Download podcast episodes using RSS feeds
- Check for duplicate episodes using tracker API
- Organize and analyze downloaded files
- Generate reports based on the downloaded content
- Data fetching from the Podchaser and Podcastindex API
- Data fetching from Podnews
- Automatic RSS censoring for matching premium sources
- Optional local database with metadata for improved flexibility
- Option to split active podcasts on current year (database required)
- Partial download of feed using --match-titles
- Torrent file creation with piece size calculation
- Optional UNIT3D web upload with Netscape cookie auth, image preprocessing, and tracker-torrent download
- Optional qBittorrent injection after upload
- Optional staging for local-folder runs using hardlinks or copies

## Requirements

- Python 3.12.0+
- Required Python packages (listed in `requirements.txt`)
- mktorrent
- ffmpeg

### Optional Requirements
- mediainfo

## Installation

1. Clone the repository:
    ```sh
    git clone git@github.com:lewler/bulldozer.git
    cd bulldozer
    ```

2. Install the required Python packages:
    ```sh
    pip install -r requirements.txt
    ```

3. Install additional dependencies:
    ```sh
    sudo apt-get install libwebp-dev libavif-dev
    ```

4. Install podcast-dl:
    ```sh
    curl -L "$(curl -s https://api.github.com/repos/lightpohl/podcast-dl/releases/latest | yq -r '.assets[] | select(.name | test("linux-x64$")) | .browser_download_url')" -o ~/.local/bin/podcast-dl && chmod +x ~/.local/bin/podcast-dl
    ```

5. Create your own config file, and add the things you need to override:
    ```sh
    touch config.yaml
    ```

6. If you want to use the Podchaser API you will need a token, which is free up to 25k points per month.

## Configuration

Edit the `config.yaml` file to set up your preferences and API keys. The configuration file includes pretty much all settings that are needed to customize the behavior of the script. The settings most users need to change are at the top of the configuration file. The file has comments, and it's hopefully easy enough to understand what everything does.

Note that you do not need to copy the entire file, and you do not need to add values that you don't need to change. This approach means less work when new things are added to `config.default.yaml`.

### UNIT3D Upload Configuration

Bulldozer can now submit completed podcast uploads directly to a UNIT3D tracker such as Unwalled by using the normal web upload form. The upload stage is optional and disabled by default.

Example override:

```yaml
upload:
  active: true
  backend: unit3d_web
  base_url: https://unwalled.cc
  cookie_file: data/cookies/UNW.txt
  download_uploaded_torrent: true

client:
  active: true
  backend: qbittorrent
  url: http://127.0.0.1:8080
```

Notes:
- Export the tracker session cookies in Netscape `cookies.txt` format.
- Tracker category, type, anonymity, personal release, ads-removed, and extra keywords are resolved at runtime during the upload flow.
- For no-meta trackers like Unwalled, the uploader will require a square cover JPG and a 16:9 banner JPG unless `upload.require_images` is disabled.
- After a successful upload, Bulldozer can download the tracker-returned `.torrent` file separately so you can seed with the tracker version.
- qBittorrent injection uses the parent of the processed folder as the save path so qBittorrent can recheck and seed the existing data.
- qBittorrent credentials can be set in `client.username` / `client.password` or provided via `QBITTORRENT_USERNAME` / `QBITTORRENT_PASSWORD` or `QBT_USER` / `QBT_PASS`.

### Local Folder Staging

When you point Bulldozer at an existing local podcast folder, Bulldozer normally organizes that folder in place. If upload or qBittorrent injection is enabled, staging is the safe way to preserve your library while still producing a tracker-shaped working tree that qBittorrent can seed.

Example override:

```yaml
staging:
  active: true
  path: /mnt/Pool/Media/Torrents/.bulldozer-staging
  mode: hardlink
```

Notes:
- `staging.mode: hardlink` creates a seedable working tree without duplicating the underlying media data.
- If `staging.path` is not set and staging is forced by upload or client injection, Bulldozer stages into a sibling `.bulldozer-staging` folder next to the source input.
- qBittorrent injection uses the staged folder, so the returned tracker torrent sees the same layout Bulldozer uploaded.
- Hardlink staging skips in-place audio tag rewrites by default so the source library is not modified through shared inodes.
- `staging.overwrite: true` replaces an existing staged folder with the same name before a new run.

## Upgrading

Upgrading should be fairly simple, but if you're jumping versions it might get messy. In that case, do a fresh install and copy your settings over. To upgrade do the following:

1. Update the codebase
    ```sh
    git pull
    ````

2. Make sure requirements are up-to-date
    ```sh
     pip install -r requirements.txt --upgrade
    ```

3. Run the config checker to see if your config is outdated
    ```sh
    python bulldozer --check-config
    ```
    The config checker will let you know if there are settings in your config that are outdated (ie, the don't exist in the default config).


## Usage

### Command Line Interface

Run the script using the command line interface:

```sh
python bulldozer <input>
```
`<input>`: RSS feed URL, directory path, local RSS file path, or name to dupecheck.

Note that if your on Linux, you should be able to run the script in this way:
```sh
chmod +x bulldozer
./bulldozer <input>
```

### Options
- `--censor-rss`: Make sure the RSS feed is censored.
- `--report-only`: Only check the files.
- `--download-only`: Only downloads the files.
- `--refresh`: Don't use the data in the database.
- `--check-files`: Only check the files.
- `--dupecheck`: Search the API for <input>.
- `--make-torrent`: Only create a torrent file.
- `--check-config`: Check if user config is valid.
- `--log-level`: Set the logging level (e.g., DEBUG, INFO, WARNING, ERROR, CRITICAL).
- `--search-term`: Use <input> as search term instead of podcast name.
- `--name`: Use <input> as the podcast name.
- `--match-titles`: Will only keep episodes matching <input> in the feed.
- `--after`: Will only keep episodes released after <input> in the feed (YYYY-MM-DD).
- `--before`: Will only keep episodes released before <input> in the feed (YYYY-MM-DD).
- `--latest-episode-only`: Will only keep the newest episode in the feed.
- `--threads`: Overrides the setting in config.yaml for the number of threads podcast-dl uses.
- `--upload`: Runs the configured upload backend after torrent creation.
- `--upload-dry-run`: Validates auth, title, keywords, images, and the prepared UNIT3D payload without submitting.

## Running With Docker

Docker should allow you to run bulldozer on mac or without installing all the native dependencies. This is a quick guide assuming you're new to docker. 

To get started, first install [Docker Desktop](https://www.docker.com/products/docker-desktop/)

To run interactively, you'll want to construct a command like this: 

```
docker run --pull always -it --rm -v ./config.yaml:/usr/bulldozer/config.yaml -v ~/temp_podcasts/:/output/podcasts/ ghcr.io/lewler/bulldozer:main /bin/bash
```
Explanation: 
- [`--pull always`](https://docs.docker.com/reference/cli/docker/container/run/#pull) tries to pull updates to the image. 
- `-it` and `/bin/bash` in the command drop you into a shell inside the container. This is useful because bulldozer requires interaction. If you leave these off, the default command will validate your config. 
- [`--rm`](https://docs.docker.com/reference/cli/docker/container/run/#rm) automatically cleans up the container when it exits. This is a good default or docker has a habit of filling up your hard drive.
- [`-v`](https://docs.docker.com/reference/cli/docker/container/run/#volume) mounts the volume following the pattern `/path/on/your/computer/:/path/on/container/`.
    - `/path/to/config.yaml:/usr/bulldozer/config.yaml` is required in order to pass your local bulldozer config.
    - `~/temp_podcasts/:/output/podcasts/` can be whatever you want. Note: the path you specify in your config is the path in the container not the host!
- `ghcr.io/lewler/bulldozer:main` is the name for the image. `main` will automatically update when new versions are pushed to the main branch on github. The short commit sha should also work as a tag.

For Mac users: You can probably get it to run with `--platform linux/x86_64` in the `docker run` command using docker desktop for mac (I tested it once). 


## Project Structure

- bulldozer: Main script
- classes/: Contains various classes used in the project.
  - apis/: Contains classes to interact with various apis.
    - podcastindex.py: Interacts with the Podcastindex API
    - podchaser.py: Interacts with the Podchaser API
  - scrapers/: Contains classes to scrape websites.
    - podnews.py: Scrapes data from Podnews.
  - cache.py: Handles the caching.
  - data_formatter.py: Methods for transforming data.
  - database.py: Handles the database logic.
  - dupe_checker.py: Checks for duplicates.
  - file_analyzer.py: Analyzes downloaded files.
  - file_organizer.py: Organizes downloaded files.
  - podcast_image.py: Handles podcast image processing.
  - podcast_metadata.py: Manages podcast metadata.
  - podcast.py: Represents a podcast and its metadata.
  - report_template.py: Templates for generating reports.
  - report.py: Generates reports based on downloaded content.
  - rss.py: Handles RSS feed operations.
  - torrent_creator.py: Creates torrent files.
  - utils.py: Utility functions.
- logs/: Contains log files.
- config.example.yaml: Example configuration file.
- requirements.txt: List of required Python packages.

## License

This project is licensed under the MIT License. See the LICENSE file for details.

## Contributing

Contributions are welcome! Please open an issue or submit a pull request for any changes.

## Acknowledgements

- [Jinja2](https://pypi.org/project/Jinja2/) for templating.
- [PyYAML](https://pypi.org/project/PyYAML/) for YAML parsing.
- [Pillow](https://pypi.org/project/pillow/) for image processing.
- [yaspin](https://pypi.org/project/yaspin/) for terminal spinners.
- [mutagen](https://pypi.org/project/mutagen/) for audio metadata handling.
- [titlecase](https://pypi.org/project/titlecase/) for title casing.
- [Podchaser API](https://api-docs.podchaser.com/docs/overview) for additional metadata.
- [Podcastindex API](https://podcastindex.org) for additional metadata.
- [Podnews](https://podnews.net) for additional metadata.
- [TinyDB](https://pypi.org/project/tinydb/) for database support.
