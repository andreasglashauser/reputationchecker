from typing import Tuple
from .base import DNSBLHandler

class DroneBLHandler(DNSBLHandler):
    """Handler for DroneBL DNSBL service."""
    
    RETURN_CODES = {
        '2': 'Sample',
        '3': 'IRC Drone',
        '5': 'Bottler',
        '6': 'Unknown spambot or drone',
        '7': 'DDOS Drone',
        '8': 'SOCKS Proxy',
        '9': 'HTTP Proxy',
        '10': 'ProxyChain',
        '11': 'Web Page Proxy',
        '12': 'Open DNS Resolver',
        '13': 'Brute force attackers',
        '14': 'Open Wingate Proxy',
        '15': 'Compromised router / gateway',
        '16': 'Autorooting worms',
        '17': 'Automatically determined botnet IPs (experimental)',
        '18': 'DNS/MX type hostname detected on IRC',
        '255': 'Unknown'
    }
    
    def check(self, target: str) -> Tuple[bool, str]:
        """
        Check if a target is listed in DroneBL.
        
        Args:
            target: The target to check (IP or domain)
            
        Returns:
            Tuple[bool, str]: (is_listed, details)
        """
        try:
            lookup = self._get_lookup_name(target)
            return_ip = self._get_a_record(lookup)
            
            if not return_ip:
                return False, "Not Listed"
            
            code = return_ip.split('.')[-1]
            
            threat_type = self.RETURN_CODES.get(code, "Unknown Threat Type")
            
            return True, f"{threat_type} (Code: {code}, Return IP: {return_ip})"
            
        except Exception as e:
            return False, f"Error: {str(e)}" 