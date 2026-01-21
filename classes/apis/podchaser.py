# podchaser.py
import json
import time
from pathlib import Path
import requests
from ..utils import spinner, log, announce, ask_yes_no, get_from_cache, write_to_cache

class Podchaser:
    TOKEN_CACHE_KEY = "podchaser-auth.json"
    TOKEN_LIFETIME_SECONDS = 365 * 24 * 60 * 60

    def __init__(self, client_id, client_secret, fields, url, limit, cache_directory=None):
        """
        Initialize the Podchaser API with the client credentials and fields.

        :param client_id: The client ID for the API.
        :param client_secret: The client secret for the API.
        :param fields: The fields to use for the query.
        :param url: The URL of the API.
        :param limit: The limit of results to return.
        :param cache_directory: The directory to store the auth token.

        The Podchaser class is responsible for querying the Podchaser API.
        """
        self.client_id = client_id
        self.client_secret = client_secret
        self.results = None
        self.fields = fields
        self.url = url
        self.limit = limit
        self.cache_directory = Path(cache_directory) if cache_directory else None

    def get_token_cache_path(self):
        if self.cache_directory:
            self.cache_directory.mkdir(parents=True, exist_ok=True)
            return self.cache_directory / self.TOKEN_CACHE_KEY
        return Path(self.TOKEN_CACHE_KEY)

    def load_cached_token(self):
        cache_path = self.get_token_cache_path()
        if not cache_path.exists():
            return None
        try:
            data = json.loads(cache_path.read_text())
        except json.JSONDecodeError:
            return None
        if not data.get("access_token") or not data.get("expires_at"):
            return None
        return data

    def save_cached_token(self, token, expires_at):
        cache_path = self.get_token_cache_path()
        payload = {
            "access_token": token,
            "expires_at": expires_at,
        }
        cache_path.write_text(json.dumps(payload, indent=4))

    def get_access_token(self):
        cached = self.load_cached_token()
        if cached and cached.get("expires_at", 0) > int(time.time()):
            return cached.get("access_token")

        if not self.client_id or not self.client_secret:
            log("Podchaser client credentials are missing.", "error")
            return None

        mutation = """
            mutation RequestAccessToken($client_id: String!, $client_secret: String!) {
                requestAccessToken(
                    input: {
                        grant_type: CLIENT_CREDENTIALS
                        client_id: $client_id
                        client_secret: $client_secret
                    }
                ) {
                    access_token
                    token_type
                    expires_in
                }
            }
        """
        payload = {
            "query": mutation,
            "variables": {
                "client_id": self.client_id,
                "client_secret": self.client_secret,
            },
        }
        headers = {
            "Content-Type": "application/json",
        }
        response = requests.post(self.url, json=payload, headers=headers)
        if response.status_code != 200:
            log(f"Podchaser auth failed with status code {response.status_code}", "error")
            log(response.text, "debug")
            return None

        data = response.json()
        if data.get("errors"):
            log("Podchaser auth response returned errors.", "error")
            log(data["errors"], "debug")
            return None

        token_data = data.get("data", {}).get("requestAccessToken", {})
        token = token_data.get("access_token")
        if not token:
            log("Podchaser auth response did not include an access token.", "error")
            log(data, "debug")
            return None

        expires_in = token_data.get("expires_in") or self.TOKEN_LIFETIME_SECONDS
        expires_at = int(time.time()) + int(expires_in)
        self.save_cached_token(token, expires_at)
        return token

    def build_fields(self, fields, indent_level=7):
        """
        Build the fields for the query.

        :param fields: The fields to build.
        :param indent_level: The level of indentation.
        :return: The fields query.
        """
        query = ""

        for field in fields:
            indent = "    " * indent_level
            if query == "" and indent_level == 7:
                indent = ""
            if isinstance(field, dict):
                for key, sub_fields in field.items():
                    query += f"{indent}{key} {{\n"
                    query += self.build_fields(sub_fields, indent_level + 1)
                    query += f"{indent}}}\n"
            else:
                query += f"{indent}{field}\n"

        if indent_level == 7:
            query = query.strip()
        return query
    
    def query_api(self, name, key):
        """
        Query the Podchaser API for a podcast by name.

        :param name: The name of the podcast to search for.
        :param key: The key to use for the cache.
        :return: The data from the API.
        """
        with spinner(f"Searching for podcast {name} on Podchaser") as spin:
                token = self.get_access_token()
                if not token:
                    spin.fail('✖')
                    return None
                headers = {
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {token}"
                }
                fields_query = self.build_fields(self.fields)
                query = f"""
                    query Podcasts($searchTerm: String!) {{
                        podcasts(searchTerm: $searchTerm first: {self.limit}) {{
                            paginatorInfo {{
                                currentPage
                                hasMorePages
                                lastPage
                            }}
                            data {{
                                {fields_query}
                            }}
                        }}
                    }}
                """
                variables = {
                    "searchTerm": name
                }

                payload = {
                    "query": query,
                    "variables": variables,
                }

                response = requests.post(self.url, json=payload, headers=headers)
                if response.status_code == 200:
                    data = response.json()
                    if 'errors' in data:
                        log(f"Podchaser query failed with errors", "error")
                        log(data['errors'], "debug")
                        spin.fail('✖')
                        return None
                else:
                    log(f"Podchaser query failed with status code {response.status_code}", "error")
                    log(response.text, "debug")
                    spin.fail('✖')
                    announce(f"Failed to query Podchaser - probably due to not enough points. Consider disabling it.", "error")
                    return None
                write_to_cache(key, json.dumps(data, indent=4))
                spin.ok('✔')
        return data

    def find_podcast(self, name):
        """
        Find a podcast on Podchaser by name.

        :param name: The name of the podcast to search for.
        :return: The podcast object.
        """
        key = f"podchaser-search-{name.lower().replace(' ', '_')}.json"
        data = get_from_cache(key)
        if data:
            log(f"Found cached data for search '{name}' in {key}", "debug")
            data = json.loads(data)
        if not data:
            log(f"No cached found data for search '{name}' - quering Podchaser", "debug")
            data = self.query_api(name, key)
        
        if not data:
            return None
        podcasts = data.get('data', {}).get('podcasts', {}).get('data', [])

        announce(f"Found {len(podcasts)} podcasts matching '{name}' at Podchaser", "info")
        for podcast in podcasts:
            title = podcast.get('title')
            url = podcast.get('url')

            if ask_yes_no(f"Continue with {title} ({url})"):
                return podcast
            
        return None

            
            
