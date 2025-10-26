from typing import Dict

class SessionManager:
    def __init__(self):
        self.ioc_store = {}
    
    def store_iocs(self, iocs: Dict):
        """Store IOCs in memory"""
        self.ioc_store = iocs
    
    def get_iocs(self) -> Dict:
        """Retrieve stored IOCs"""
        return self.ioc_store
    
    def clear(self):
        """Clear session data"""
        self.ioc_store = {}
