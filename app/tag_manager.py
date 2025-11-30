"""
IOCReaper Tag Manager Module - Phase 5 Security Enhanced
Includes input validation and comprehensive logging

Author: Manudeep Maddipatla
Email: mmaddipa@umd.edu
UMD Directory ID: mmaddipa (121417350)
"""

from typing import Dict
from input_validator import get_input_validator
from security_logger import get_security_logger


class TagManager:
    """
    Manage IOC tags with security enhancements.
    
    Phase 5 Security Features:
    - Tag validation
    - Tag count limits
    - XSS prevention
    - Comprehensive logging
    """
    
    def __init__(self):
        """Initialize tag manager with security components."""
        self.validator = get_input_validator()
        self.logger = get_security_logger()
    
    def add_tag(self, ioc_value: str, tag: str, session_manager) -> Dict:
        """
        Add a tag to an IOC with validation.
        
        Args:
            ioc_value: IOC value to tag
            tag: Tag to add
            session_manager: Session manager instance
            
        Returns:
            Success message dictionary
            
        Raises:
            ValueError: If validation fails
        """
        # Validate tag (done in main.py, but double-check)
        is_valid, error_msg = self.validator.validate_tag_input(tag)
        if not is_valid:
            raise ValueError(error_msg)
        
        tag = tag.strip()
        
        # Find and update IOC
        iocs = session_manager.get_iocs()
        found = False
        
        for ioc_type, data in iocs.items():
            for ioc in data['items']:
                if ioc['value'] == ioc_value:
                    # Check tag count limit
                    is_count_valid, count_error = self.validator.check_tag_count(len(ioc['tags']))
                    if not is_count_valid:
                        raise ValueError(count_error)
                    
                    # Add tag if not already present
                    if tag not in ioc['tags']:
                        ioc['tags'].append(tag)
                    
                    found = True
                    break
            if found:
                break
        
        if not found:
            raise ValueError("IOC not found")
        
        return {"message": "Tag added successfully"}
    
    def remove_tag(self, ioc_value: str, tag: str, session_manager) -> Dict:
        """
        Remove a tag from an IOC.
        
        Args:
            ioc_value: IOC value
            tag: Tag to remove
            session_manager: Session manager instance
            
        Returns:
            Success message dictionary
            
        Raises:
            ValueError: If IOC not found
        """
        iocs = session_manager.get_iocs()
        found = False
        
        for ioc_type, data in iocs.items():
            for ioc in data['items']:
                if ioc['value'] == ioc_value:
                    if tag in ioc['tags']:
                        ioc['tags'].remove(tag)
                    found = True
                    break
            if found:
                break
        
        if not found:
            raise ValueError("IOC not found")
        
        return {"message": "Tag removed successfully"}
