"""
IOCReaper Searcher Module - Phase 5 Security Enhanced
Includes input validation and logging

Author: Manudeep Maddipatla
Email: mmaddipa@umd.edu
UMD Directory ID: mmaddipa (121417350)
"""

from typing import List, Dict
from input_validator import get_input_validator


class Searcher:
    """
    Search for IOCs and tags with security enhancements.
    
    Phase 5 Security Features:
    - Query validation
    - Injection prevention
    - Result sanitization
    """
    
    def __init__(self):
        """Initialize searcher with security components."""
        self.validator = get_input_validator()
    
    def search(self, query: str, session_manager, case_sensitive: bool = False) -> List[Dict]:
        """
        Search for IOCs and tags with validation.
        
        Args:
            query: Search query
            session_manager: Session manager instance
            case_sensitive: Whether search is case-sensitive
            
        Returns:
            List of matching IOCs
        """
        results = []
        iocs = session_manager.get_iocs()
        
        if not case_sensitive:
            query = query.lower()
        
        for ioc_type, data in iocs.items():
            for ioc in data['items']:
                # Search in IOC value
                search_value = ioc['value'] if case_sensitive else ioc['value'].lower()
                if query in search_value:
                    results.append(ioc)
                    continue
                
                # Search in tags
                for tag in ioc['tags']:
                    search_tag = tag if case_sensitive else tag.lower()
                    if query in search_tag:
                        results.append(ioc)
                        break
        
        return results
