from typing import Tuple, Dict
from .base import DNSBLHandler

class SpamCopHandler(DNSBLHandler):
    """Handler for SpamCop DNSBL service."""
    
    RETURN_CODES: Dict[str, str] = {
        '127.0.0.2': 'General spam source'
    }
    
    def check(self, target: str) -> Tuple[bool, str]:
        """
        Check if a target is listed in SpamCop.
        
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