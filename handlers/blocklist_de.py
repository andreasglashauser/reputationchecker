from typing import Tuple
from .base import DNSBLHandler

class BlocklistDEHandler(DNSBLHandler):
    """Handler for Blocklist.de DNSBL service."""
    
    RETURN_CODES = {
        '127.0.0.2': 'amavis',
        '127.0.0.3': 'apacheddos',
        '127.0.0.4': 'asterisk',
        '127.0.0.5': 'badbot',
        '127.0.0.6': 'ftp',
        '127.0.0.7': 'imap',
        '127.0.0.8': 'ircbot',
        '127.0.0.9': 'mail',
        '127.0.0.10': 'pop3',
        '127.0.0.11': 'regbot',
        '127.0.0.12': 'rfi-attack',
        '127.0.0.13': 'sasl',
        '127.0.0.14': 'ssh',
        '127.0.0.15': 'w00tw00t',
        '127.0.0.16': 'portflood',
        '127.0.0.17': 'sql-injection',
        '127.0.0.18': 'webmin',
        '127.0.0.19': 'trigger-spam',
        '127.0.0.20': 'manuall',
        '127.0.0.21': 'bruteforcelogin',
        '127.0.0.22': 'mysql'
    }
    
    def check(self, target: str) -> Tuple[bool, str]:
        """
        Check if a target is listed in Blocklist.de.
        
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