from typing import Tuple, Dict, List
import logging
from .base import DNSBLHandler

class HostkarmaHandler(DNSBLHandler):
    """Handler for Hostkarma DNSBL service."""
    
    RETURN_CODES: Dict[str, str] = {
        '127.0.0.1': 'Whitelist - Trusted nonspam',
        '127.0.0.2': 'Blacklist - Block spam',
        '127.0.0.3': 'Yellowlist - Mix of spam and nonspam',
        '127.0.0.4': 'Brownlist - All spam, but not yet enough to blacklist',
        '127.0.0.5': 'NOBL - IP is not a spam only source'
    }
    
    COLOR_LOGIC: Dict[str, List[str]] = {
        'red': ['127.0.0.2', '127.0.0.4'],
        'yellow': ['127.0.0.3'],
        'green': ['127.0.0.1', '127.0.0.5']
    }
    
    def __init__(self, service):
        super().__init__(service)
        self.logger = logging.getLogger('reputation_checker.hostkarma')
        self.logger.debug("Initialized Hostkarma handler")
    
    def check(self, target: str) -> Tuple[bool, str]:
        """
        Check if a target is listed in Hostkarma.
        
        Args:
            target: The target to check (IP or domain)
            
        Returns:
            Tuple[bool, str]: (is_listed, details)
        """
        self.logger.info(f"Checking target: {target}")
        
        try:
            lookup = self._get_lookup_name(target)
            self.logger.debug(f"DNS lookup: {lookup}")
            
            return_ip = self._get_a_record(lookup)
            
            if not return_ip:
                self.logger.info(f"Target {target} not listed in Hostkarma")
                return False, "Not listed"
            
            if return_ip in self.RETURN_CODES:
                listing_type = self.RETURN_CODES[return_ip]
                self.logger.info(f"Target {target} listed in Hostkarma as {listing_type}")
                return True, f"{listing_type} (Return IP: {return_ip})"
            
            self.logger.warning(f"Target {target} returned unknown code: {return_ip}")
            return True, f"Listed (Unknown return code: {return_ip})"
            
        except Exception as e:
            self.logger.error(f"Error checking Hostkarma: {str(e)}", exc_info=True)
            return False, f"Error: {str(e)}" 