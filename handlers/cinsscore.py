from typing import Tuple
import os
import platform
import requests
import logging
from datetime import datetime, timedelta
from .base import DNSBLHandler

class CINSScoreHandler(DNSBLHandler):
    """Handler for CINSscore IP reputation list."""
    
    def __init__(self, service):
        super().__init__(service)
        self.logger = logging.getLogger('reputation_checker.cinsscore')
        self.cache_dir = self._get_cache_dir()
        self.cache_file = os.path.join(self.cache_dir, 'cinsscore_badguys.txt')
        self.cache_duration = timedelta(hours=24) 
        self.logger.debug(f"Initialized CINSscore handler with cache file: {self.cache_file}")
        
    def _get_cache_dir(self) -> str:
        """Get the appropriate cache directory for the current OS."""
        system = platform.system().lower()
        
        if system == 'linux':
            xdg_cache = os.environ.get('XDG_CACHE_HOME')
            if xdg_cache:
                self.logger.debug(f"Using XDG cache directory: {xdg_cache}")
                return xdg_cache
            cache_dir = os.path.expanduser('~/.cache')
            self.logger.debug(f"Using fallback cache directory: {cache_dir}")
            return cache_dir
        elif system == 'windows':
            cache_dir = os.path.expandvars('%LOCALAPPDATA%')
            self.logger.debug(f"Using Windows cache directory: {cache_dir}")
            return cache_dir
        else:
            cache_dir = os.path.expanduser('~/.cache')
            self.logger.debug(f"Using default cache directory: {cache_dir}")
            return cache_dir
    
    def _download_list(self) -> bool:
        """Download the CINSscore list and save it to cache."""
        self.logger.info("Downloading CINSscore bad guys list")
        try:
            response = requests.get('https://cinsscore.com/list/ci-badguys.txt')
            response.raise_for_status()
            
            os.makedirs(self.cache_dir, exist_ok=True)
            self.logger.debug(f"Created cache directory: {self.cache_dir}")
            
            with open(self.cache_file, 'w') as f:
                f.write(response.text)
            
            self.logger.info(f"Successfully downloaded and cached {len(response.text.splitlines())} IPs")
            return True
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Failed to download CINSscore list: {str(e)}")
            return False
        except Exception as e:
            self.logger.error(f"Unexpected error while downloading list: {str(e)}", exc_info=True)
            return False
    
    def _is_cache_valid(self) -> bool:
        """Check if the cached list is still valid."""
        if not os.path.exists(self.cache_file):
            self.logger.debug("Cache file does not exist")
            return False
            
        mtime = datetime.fromtimestamp(os.path.getmtime(self.cache_file))
        age = datetime.now() - mtime
        is_valid = age < self.cache_duration
        
        if is_valid:
            self.logger.debug(f"Cache is valid (age: {age})")
        else:
            self.logger.debug(f"Cache is expired (age: {age})")
            
        return is_valid
    
    def _load_cached_list(self) -> set:
        """Load the IP list from cache."""
        self.logger.debug("Loading cached IP list")
        try:
            with open(self.cache_file, 'r') as f:
                ips = set(line.strip() for line in f if line.strip())
            self.logger.debug(f"Loaded {len(ips)} IPs from cache")
            return ips
        except Exception as e:
            self.logger.error(f"Error reading cached list: {str(e)}", exc_info=True)
            return set()
    
    def check(self, target: str) -> Tuple[bool, str]:
        """
        Check if a target is listed in CINSscore.
        
        Args:
            target: The target to check (IP address)
            
        Returns:
            Tuple[bool, str]: (is_listed, details)
        """
        self.logger.info(f"Checking target: {target}")
        
        if not self._is_cache_valid():
            self.logger.info("Cache invalid or missing, downloading new list")
            if not self._download_list():
                return False, "Error: Could not download CINSscore list"
        
        bad_ips = self._load_cached_list()
        
        if target in bad_ips:
            self.logger.info(f"Target {target} found in CINSscore list")
            return True, "Listed in CINSscore bad guys list"
            
        self.logger.info(f"Target {target} not found in CINSscore list")
        return False, "Not listed" 