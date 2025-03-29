from typing import Tuple
from .base import DNSBLHandler

class MailspikeHandler(DNSBLHandler):
    """Handler for Mailspike DNSBL service."""
    
    RETURN_CODES = {
        '127.0.0.10': 'L5 - Worst possible reputation',
        '127.0.0.11': 'L4 - Very bad reputation',
        '127.0.0.12': 'L3 - Bad reputation',
        '127.0.0.13': 'L2 - Suspicious behavior reputation',
        '127.0.0.14': 'L1 - Neutral - Probably spam',
        '127.0.0.15': 'LHO - Neutral',
        '127.0.0.16': 'H1 - Neutral - Probably legit',
        '127.0.0.17': 'H2 - Possible legit sender',
        '127.0.0.18': 'H3 - Good Reputation',
        '127.0.0.19': 'H4 - Very Good Reputation',
        '127.0.0.20': 'H5 - Excellent Reputation'
    }
    
    def check(self, target: str) -> Tuple[bool, str]:
        """
        Check if a target is listed in Mailspike.
        
        Args:
            target: The target to check (IP or domain)
            
        Returns:
            Tuple[bool, str]: (is_listed, details)
        """
        lookup = self._get_lookup_name(target)
        return_ip = self._get_a_record(lookup)
        
        if not return_ip:
            return False, "Not listed"
            
        if return_ip in self.RETURN_CODES:
            return True, f"{self.RETURN_CODES[return_ip]} (Return IP: {return_ip})"
            
        return True, f"Listed (Return IP: {return_ip})"