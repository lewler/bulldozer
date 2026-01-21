# dupe_checker.py
import requests
from .utils import announce, log, ask_yes_no

class DupeChecker:
    def __init__(self, search_name, url, api_key, warn=True):
        """
        Initialize the DupeChecker with the search name, URL, API key, and warning flag.
        
        :param search_name: The name to search for duplicates.
        :param url: The URL of the API to check for duplicates.
        :param api_key: The API key for authentication.
        :param warn: Flag to indicate if warnings should be issued.

        The DupeChecker class is responsible for checking for duplicates using the provided API.
        """
        self.search_name = search_name
        self.url = url
        self.api_key = api_key
        self.warn = warn

    def check_duplicates(self, report_no_dupes=False):
        """
        Check for duplicates using the provided API.
        
        :param report_no_dupes: Flag to indicate if a report should be generated when no duplicates are found.
        :return: True if duplicates were found or no duplicates were found and the user wants to continue, False otherwise.
        """
        log(f"Starting duplicate check for: {self.search_name}", "info")
        log(f"Duplicate check URL: {self.url}", "info")
        
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Accept": "application/json"
        }
        params = {
            "name": self.search_name,
        }
        log(f"Duplicate check parameters: {params}", "info")

        ask_user = False

        try:
            log(f"Making request to duplicate check API...", "info")
            response = requests.get(self.url, headers=headers, params=params)
            log(f"Received response status code: {response.status_code}", "info")
            response.raise_for_status()
            torrents = response.json()
            log(f"Response contains {len(torrents.get('data', []))} potential duplicates", "info")
            if torrents['data']:
                announce("Possible duplicates found:", "warning")
                ask_user = True
                for torrent in torrents['data']:
                    announce(f"- {torrent['attributes']['name']}: {torrent['attributes']['details_link']}")
            elif report_no_dupes:
                announce(f'Nothing found for "{self.search_name}"', 'info')
                log(f'No duplicates found for "{self.search_name}"', "info")
                
        except requests.exceptions.RequestException as e:
            announce(f"An error occurred while checking for duplicates", "error")
            log(f"Request exception type: {type(e).__name__}", "info")
            log(f"Request exception details: {str(e)}", "info")
            if hasattr(e, 'response') and e.response is not None:
                log(f"Response status code: {e.response.status_code}", "info")
                log(f"Response headers: {dict(e.response.headers)}", "info")
                try:
                    log(f"Response body: {e.response.text[:500]}", "info")
                except:
                    log(f"Could not read response body", "info")
            log(e, "debug")
            ask_user = True
        
        if self.warn and ask_user:
            if not ask_yes_no("Do you want to continue"):
                return False

        return True
