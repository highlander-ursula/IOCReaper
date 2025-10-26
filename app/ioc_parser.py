import re
from typing import List, Dict
from fangerdefanger import FangerDefanger

class IOCParser:
    def __init__(self):
        self.fangerdefanger = FangerDefanger()
        
        # Regex patterns for different IOC types
        self.patterns = {
            'ipv4': r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
            'ipv6': r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b',
            'domain': r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b',
            'url': r'https?://[^\s]+',
            'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            'md5': r'\b[a-fA-F0-9]{32}\b',
            'sha1': r'\b[a-fA-F0-9]{40}\b',
            'sha256': r'\b[a-fA-F0-9]{64}\b'
        }
    
    def extract(self, text: str, normalize: bool = False, deduplicate: bool = False) -> List[Dict]:
        """Extract IOCs from text"""
        iocs = []
        
        # Normalize text if requested
        if normalize:
            text = self.fangerdefanger.fang(text)
        
        # Extract each IOC type
        for ioc_type, pattern in self.patterns.items():
            matches = re.findall(pattern, text, re.IGNORECASE)
            for match in matches:
                iocs.append({
                    'value': match,
                    'type': ioc_type,
                    'tags': []
                })
        
        # Deduplicate if requested
        if deduplicate:
            seen = set()
            unique_iocs = []
            for ioc in iocs:
                key = (ioc['value'], ioc['type'])
                if key not in seen:
                    seen.add(key)
                    unique_iocs.append(ioc)
            iocs = unique_iocs
        
        return iocs