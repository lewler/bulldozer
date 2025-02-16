# podchaser.py
import requests
import json
from ..utils import spinner, log, announce, ask_yes_no, get_from_cache, write_to_cache

class Podchaser:
    def __init__(self, token, fields, url, limit):
        """
        Initialize the Podchaser API with the token and fields.

        :param token: The token to use for the API.
        :param fields: The fields to use for the query.
        :param url: The URL of the API.
        :param limit: The limit of results to return.

        The Podchaser class is responsible for querying the Podchaser API.
        """
        self.token = token
        self.results = None
        self.fields = fields
        self.url = url
        self.limit = limit

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
                headers = {
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {self.token}"
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

            
            

