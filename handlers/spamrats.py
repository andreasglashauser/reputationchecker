from typing import Tuple
import logging
from .base import DNSBLHandler

class SpamRATSHandler(DNSBLHandler):
    """Handler for SpamRATS reputation lists."""
    
    RETURN_CODES = {
        '127.0.0.36': 'RATS-Dyna',
        '127.0.0.37': 'RATS-NoPtr',
        '127.0.0.38': 'RATS-Spam',
        '127.0.0.43': 'RATS-Auth'
    }
    
    def __init__(self, service):
        super().__init__(service)
        self.logger = logging.getLogger('reputation_checker.spamrats')
        self.logger.debug("Initialized SpamRATS handler")
    
    def check(self, target: str) -> Tuple[bool, str]:
        """
        Check if a target is listed in SpamRATS.
        
        Args:
            target: The target to check (IP address)
            
        Returns:
            Tuple[bool, str]: (is_listed, details)
        """
        self.logger.info(f"Checking target: {target}")
        
        try:
            lookup = self._get_lookup_name(target)
            self.logger.debug(f"DNS lookup: {lookup}")
            
            return_ip = self._get_a_record(lookup)
            
            if not return_ip:
                self.logger.info(f"Target {target} not listed in SpamRATS")
                return False, "Not listed"
            
            if return_ip in self.RETURN_CODES:
                listing_type = self.RETURN_CODES[return_ip]
                self.logger.info(f"Target {target} listed in SpamRATS as {listing_type}")
                return True, f"Listed in {listing_type} (Return IP: {return_ip})"
            
            self.logger.warning(f"Target {target} returned unknown code: {return_ip}")
            return True, f"Listed (Unknown return code: {return_ip})"
            
        except Exception as e:
            self.logger.error(f"Error checking SpamRATS: {str(e)}", exc_info=True)
            return False, f"Error: {str(e)}" 