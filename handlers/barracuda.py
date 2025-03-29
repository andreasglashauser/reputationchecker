from typing import Tuple
from .base import DNSBLHandler

class BarracudaHandler(DNSBLHandler):
    """Handler for Barracuda DNSBL service."""
    
    RETURN_CODES = {
        '127.0.0.2': 'General spam source'
    }
    
    def check(self, target: str) -> Tuple[bool, str]:
        """
        Check if a target is listed in Barracuda.
        
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