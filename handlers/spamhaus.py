from typing import Tuple, Dict
from .base import DNSBLHandler

class SpamhausHandler(DNSBLHandler):
    """Handler for Spamhaus DNSBL service."""
    
    RETURN_CODES: Dict[str, str] = {
        '127.0.0.2': 'SBL (General spam source)',
        '127.0.0.3': 'PBL (Policy Block List)',
        '127.0.0.4': 'XBL (Compromised or infected machine)',
        '127.0.0.5': 'PBL (Policy Block List)',
        '127.0.0.6': 'SBL and XBL',
        '127.0.0.7': 'SBL, XBL, and PBL',
        '127.0.0.9': 'SBL and PBL',
        '127.0.0.10': 'XBL (Other exploit activities)',
    }
    
    RATE_LIMIT_CODES: Dict[str, str] = {
        '127.255.255.254': 'Query blocked or rate-limited'
    }
    
    def check(self, target: str) -> Tuple[bool, str]:
        """
        Check if a target is listed in Spamhaus.
        
        Args:
            target: The target to check (IP or domain)
            
        Returns:
            Tuple[bool, str]: (is_listed, details)
        """
        lookup = self._get_lookup_name(target)
        return_ip = self._get_a_record(lookup)
        
        if not return_ip:
            return False, "Not listed"
            
        if return_ip == "127.255.255.254":
            return False, "Query blocked or rate-limited"
            
        if return_ip in self.RETURN_CODES:
            return True, f"{self.RETURN_CODES[return_ip]} (Return IP: {return_ip})"
            
        return True, f"Listed (Return IP: {return_ip})" 