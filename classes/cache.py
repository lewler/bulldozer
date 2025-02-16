# cache.py
from pathlib import Path
from datetime import datetime
import pickle

class Cache:
    def __init__(self, config):
        """
        Initialize the Cache with the configuration settings.

        :param config: The configuration settings.

        The Cache class is responsible for caching data to reduce the number of requests.
        """
        self.config = config
        self.cache_active = self.config.get('cache', {}).get('active', False)
        self.cache_hours = self.config.get('cache', {}).get('hours', 24)
        self.cache_directory = self.config.get('cache', {}).get('directory', None)
        if self.cache_directory:
            self.cache_directory = Path(self.cache_directory)
            self.check_cache_directory()

    def check_cache_directory(self):
        """
        Check if the cache directory exists and create it if it does not.

        :return: True if the cache directory exists, False otherwise.
        """
        from .utils import announce, log

        if not self.cache_active or not self.cache_directory:
            return False
        if not self.cache_directory.exists():
            try:
                self.cache_directory.mkdir(parents=True)
            except Exception as e:
                announce(f"Failed to create cache directory, check your config", "error")
                log(f"Failed to create cache directory", "error")
                log(str(e), "error")
                return False
        return True
    
    def get_cache_file(self, key):
        """
        Get the cache file for the given key.

        :param key: The key to get the cache file for.
        :return: The cache file.
        """
        if not self.cache_directory:
            return None
        return self.cache_directory / key
    
    def is_cache_valid(self, key):
        """
        Check if the cache is valid for the given key.

        :param key: The key to check the cache for.
        :return: True if the cache is valid, False otherwise.
        """
        cache_file = self.get_cache_file(key)
        if not cache_file:
            return False
        if not cache_file.exists():
            return False
        if (datetime.now() - datetime.fromtimestamp(cache_file.stat().st_mtime)).total_seconds() > self.cache_hours * 3600:
            return False
        return True
    
    def read_cache(self, key, mode='r'):
        """
        Read the cache for the given key.

        :param key: The key to read the cache for.
        :return: The data from the cache.
        """
        cache_file = self.get_cache_file(key)
        if not cache_file or cache_file.stat().st_size == 0:
            return None
        with cache_file.open(mode) as f:
            if mode == 'r':
                return f.read()
            if mode == 'rb':
                return pickle.load(f)
        
    def get(self, key, mode='r'):
        """
        Get data from the cache.

        :param key: The key to get the data for.
        :param mode: The mode to get the data in.
        :return: The data from the cache.
        """
        if not self.is_cache_valid(key):
            return None
        return self.read_cache(key, mode)
        
    def write(self, key, data, mode='w'):
        """
        Write data to the cache.

        :param key: The key to write the data for.
        :param data: The data to write to the cache.
        :param mode: The mode to write the data in.
        :return: True if the data was written to the cache, False otherwise.
        """
        cache_file = self.get_cache_file(key)
        if not cache_file:
            return False
        with cache_file.open(mode) as f:
            if mode == 'w':
                f.write(data)
            if mode == 'wb':
                pickle.dump(data, f)
        return True
    
    def clear_cache(self):
        """
        Clear the cache.
        """
        if not self.cache_active or not self.cache_directory:
            return False
        for file in self.cache_directory.iterdir():
            file.unlink()
        return True
    
    def clear_cache_file(self, key):
        """
        Clear the cache file for the given key.

        :param key: The key to clear the cache file for.
        """
        cache_file = self.get_cache_file(key)
        if not cache_file:
            return False
        if cache_file.exists():
            cache_file.unlink()
        return True
    