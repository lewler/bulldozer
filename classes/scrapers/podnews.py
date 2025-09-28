# podnews.py
import requests
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from ..utils import spinner, log, announce, ask_yes_no, get_from_cache, write_to_cache

class Podnews:
    def __init__(self, url):
        self.url = url
    
    def scrape(self, url, key):
        """
        Scrape Podnews

        :param url: The url to scrape.
        :param key: The key to use for the cache.
        :return: The data from the site.
        """
        with spinner(f"Getting data from Podnews") as spin:
            cookies = {
                "human": "true"
            }

            headers = {
                "User-Agent": "Mozilla/5.0"
            }
            response = requests.get(url, cookies=cookies, headers=headers)
            if response.status_code != 200:
                spin.fail('✖')
                log(f"Podnews scraping failed with status code {response.status_code}", "error")
                log(response.text, "debug")

            write_to_cache(key, response.content, 'wb')
            spin.ok('✔')
        return response.content
    
    def get_data(self, key, url):
        """
        Get the data for the specified key.

        :param key: The key to use for the cache.
        :param url: The url to scrape.
        :return: The data from the site.
        """
        data = get_from_cache(key, 'rb')
        if data:
            log(f"Found cached data in {key}", "debug")
        if not data:
            log(f"No cached data found, scraping Podnews", "debug")
            data = self.scrape(url, key)

        return data
    
    def get_data_for_selected_podcast(self, selected_podcast, name):
        """
        Get the data for the selected podcast.

        :param selected_podcast: The selected podcast object.
        :return: The data for the selected podcast.
        """
        url = selected_podcast['url']
        key = f"podnews-details-{name.lower().replace(' ', '_')}.json"
        log(f"Getting details for '{name}' at {url}", "debug")
        data = self.get_data(key, url)
        if not data:
            return None
        
        soup = BeautifulSoup(data, 'html.parser')

        rating = None
        rating_count = None

        rating_div = soup.find('div', class_='star-ratings-css-bottom')

        if rating_div:
            rating_link = rating_div.find('a')
            if rating_link and rating_link.text:
                rating = rating_link.text.strip()

            small_tag = rating_div.find('small')
            if small_tag:
                # Use regex to extract the number
                import re
                match = re.search(r'via ([\d,]+) ratings', small_tag.text)
                if match:
                    rating_count = match.group(1)

        selected_podcast['appleRating'] = rating
        selected_podcast['appleRatingCount'] = rating_count
        return selected_podcast
        
    def find_podcast(self, name):
        """
        Find a podcast on Podnews by name.

        :param name: The name of the podcast to search for.
        :return: The podcast object.
        """
        key = f"podnews-search-{name.lower().replace(' ', '_')}.json"
        url = f"{self.url}{name.lower().replace(' ', '+')}"
        log(f"Searching Podnews for '{name}' at {url}", "debug")
        data = self.get_data(key, url)
        if not data:
            return None
        
        soup = BeautifulSoup(data, "html.parser")
        results_container = soup.find("h2", text="Podcasts")
        if not results_container:
            announce("No podcasts found at Podnews.", "info")
            return None

        podcasts_div = results_container.find_next("div", style=lambda v: v and "grid" in v)
        if not podcasts_div:
            announce("No podcasts found at Podnews.", "info")
            return None
        
        all_links = podcasts_div.find_all("a", href=True)
        podcast_links = []
        for index, link in enumerate(all_links):
            img_tag = link.find("img", alt=True)
            if not img_tag:
                continue
            podcast_links.append(link)

        if not podcast_links:
            announce("No podcasts found at Podnews.", "info")
            return None

        announce(f"Found {len(podcast_links)} podcasts matching '{name}' at Podnews", "info")

        selected_podcast = {}

        for index, link in enumerate(podcast_links):
            img_tag = link.find("img", alt=True)
            podcast_name = img_tag["alt"] if img_tag else "Unknown Name"
            podcast_url = 'https://podnews.net' + link["href"]
            parsed_url = urlparse(podcast_url)
            podcast_id = id = parsed_url.path.split('/')[-1]

            if ask_yes_no(f"Continue with {podcast_name} ({podcast_url})"):
                selected_podcast = {
                    "id": podcast_id,
                    "name": podcast_name,
                    "url": podcast_url
                }
                break

        if not selected_podcast:
            announce("No podcast selected.", "info")
            return None
        
        return self.get_data_for_selected_podcast(selected_podcast, name)

            
            

