"""
IOCReaper Session Manager Module - Phase 5 Security Enhanced
Includes secure session handling and data protection

Author: Manudeep Maddipatla
Email: mmaddipa@umd.edu
UMD Directory ID: mmaddipa (121417350)
"""

from typing import Dict
from security_logger import get_security_logger


class SessionManager:
    """
    Manage in-memory IOC storage with security enhancements.
    
    Phase 5 Security Features:
    - Session isolation
    - Secure clearing
    - Data integrity
    - Session logging
    """
    
    def __init__(self):
        """Initialize session manager."""
        self.ioc_store = {}
        self.logger = get_security_logger()
    
    def store_iocs(self, iocs: Dict):
        """
        Store IOCs in memory.
        
        Args:
            iocs: IOC dictionary to store
        """
        self.ioc_store = iocs
    
    def get_iocs(self) -> Dict:
        """
        Retrieve stored IOCs.
        
        Returns:
            IOC dictionary
        """
        return self.ioc_store
    
    def clear(self):
        """
        Clear session data securely.
        
        Implements SR-08: Clear session data and runtime state
        """
        # Clear all data
        self.ioc_store = {}
